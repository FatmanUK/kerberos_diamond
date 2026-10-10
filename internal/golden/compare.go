package golden

import (
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Fields is one decoded exchange flattened to named, normalised
// values.
//
// The comparison is of decoded structures and not of octets, and that
// is not a shortcut. Every krb5_c_encrypt prepends a fresh random
// confounder (lib/crypto/krb/enc_dk_hmac.c:144), so the ticket
// enc-part, the reply enc-part and any PA-ENC-TIMESTAMP differ on
// every run even with identical keys and identical plaintext.
// Upstream reached the same conclusion about its own tests:
// k5test.py's expected_trace matching is deliberately order-tolerant
// substring matching (_check_trace, :727-733), not a transcript diff.
//
// The architectural precedent is tests/etinfo.c with
// tests/t_etype_info.py: a small program that decodes one reply and
// prints a canonical line-oriented rendering, which is then compared.
// This emits the same rendering from both sides.
type Fields struct {
	order  []string
	values map[string]string
}

func newFields() *Fields {
	return &Fields{values: map[string]string{}}
}

func (f *Fields) set(name, value string) {
	if _, seen := f.values[name]; !seen {
		f.order = append(f.order, name)
	}
	f.values[name] = value
}

// absent is what a field that was not on the wire renders as.
//
// Presence is compared before value, because whether a field travels
// at all is most of what the optionality rules in internal/wire
// decide, and a field rendered as its zero value would compare equal
// to a field that was genuinely zero.
const absent = "<absent>"

// Render returns the canonical lines, in a stable order.
func (f *Fields) Render() []string {
	out := make([]string, 0, len(f.order))
	for _, n := range f.order {
		out = append(out, n+": "+f.values[n])
	}
	return out
}

// String is Render joined by newlines, for a test failure message.
func (f *Fields) String() string {
	return strings.Join(f.Render(), "\n")
}

// Diff is one field the two implementations disagree about.
type Diff struct {
	Field   string
	Oracle  string
	Diamond string

	// Reason is set only on a waived difference, and holds the
	// exemption's justification.
	Reason string
}

func (d Diff) String() string {
	out := fmt.Sprintf("%s:\n  oracle:  %s\n  diamond: %s",
		d.Field, d.Oracle, d.Diamond)
	if d.Reason != "" {
		out += "\n  waived:  " + d.Reason
	}
	return out
}

// Exemption declares a field the comparison deliberately does not
// make, and why.
//
// It is for a divergence that is a decision rather than a defect --
// something this implementation does differently on purpose. An
// exemption is not the same as skipping a field: every one is
// reported on every run, so the output always says what was not
// compared and a reader can disagree with the reason. Reaching for
// one to make a failing diff go away is a misuse, and the Reason
// field is what makes that obvious when it happens.
type Exemption struct {
	Field  string
	Reason string
}

// Compare lists every field the two sides disagree about, including
// fields only one of them has at all.
//
// A field missing from one rendering is reported rather than skipped:
// a comparison that only walked the fields both sides produced would
// pass a reply that left half of itself out.
//
// Exempt differences come back separately rather than being dropped,
// so a caller cannot report the diffs without the exemptions in hand.
func Compare(
	oracle, diamond *Fields,
	exempt ...Exemption,
) (diffs []Diff, waived []Diff) {
	skip := map[string]string{}
	for _, e := range exempt {
		skip[e.Field] = e.Reason
	}
	for _, d := range compareAll(oracle, diamond) {
		if reason, ok := skip[d.Field]; ok {
			d.Reason = reason
			waived = append(waived, d)
			continue
		}
		diffs = append(diffs, d)
	}
	return diffs, waived
}

func compareAll(oracle, diamond *Fields) []Diff {
	names := map[string]bool{}
	for _, n := range oracle.order {
		names[n] = true
	}
	for _, n := range diamond.order {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	var diffs []Diff
	for _, n := range sorted {
		a, aok := oracle.values[n]
		b, bok := diamond.values[n]
		if !aok {
			a = "<no such field>"
		}
		if !bok {
			b = "<no such field>"
		}
		if a != b {
			diffs = append(diffs,
				Diff{Field: n, Oracle: a, Diamond: b})
		}
	}
	return diffs
}

// Exchange is one side of a comparison: the reply, its decrypted
// enc-part, and the decrypted ticket.
type Exchange struct {
	Rep wire.ASRep
	Enc wire.EncKDCRepPart
	Tkt wire.EncTicketPart
}

// Normalize flattens an exchange, replacing everything that varies
// run to run with a description of what varied.
//
// What goes, and why it means nothing:
//
//   - the nonce, which the client picks at random and masks to 31
//     bits (lib/krb5/krb/send_tgs.c:33-50);
//   - every ciphertext, replaced by its enctype, kvno and length --
//     the length is deterministic and worth comparing even though the
//     bytes are not;
//   - every session key, replaced by its enctype and length;
//   - the realm, wherever it appears, principal names included.
//
// What stays, because normalising it would hide a bug:
//
//   - every timestamp, rebased as an offset from the authtime, so
//     that the *relationships* between them are compared;
//   - whether each optional field was on the wire at all.
func Normalize(x Exchange, realm string) *Fields {
	f := newFields()
	base := x.Enc.AuthTime
	f.set("crealm", scrub(x.Rep.CRealm, realm))
	f.set("cname", scrubName(x.Rep.CName, realm))
	f.set("padata", padataSummary(x.Rep.PAData))
	f.set("rep.enc-part", encSummary(x.Rep.EncPart))
	normalizeTicket(f, x, realm)
	normalizeEnc(f, x, realm, base)
	return f
}

func normalizeTicket(f *Fields, x Exchange, realm string) {
	f.set("ticket.realm", scrub(x.Rep.Ticket.Realm, realm))
	f.set("ticket.sname", scrubName(x.Rep.Ticket.SName, realm))
	f.set("ticket.enc-part", encSummary(x.Rep.Ticket.EncPart))

	base := x.Tkt.AuthTime
	f.set("tkt.flags", flagNames(x.Tkt.Flags))
	f.set("tkt.key", keySummary(x.Tkt.Key))
	f.set("tkt.crealm", scrub(x.Tkt.CRealm, realm))
	f.set("tkt.cname", scrubName(x.Tkt.CName, realm))
	f.set("tkt.transited.type",
		fmt.Sprintf("%d", x.Tkt.Transited.Type))
	// The contents are compared and not only their length. They
	// are realm names rather than key material, they are
	// deterministic, and the compressed encoding can name a
	// *different* realm in the same number of octets -- so a
	// length comparison would pass a path that went somewhere
	// else entirely.
	f.set("tkt.transited",
		scrub(string(x.Tkt.Transited.Contents), realm))
	f.set("tkt.authtime", "base")
	f.set("tkt.starttime", offset(x.Tkt.StartTime, base))
	f.set("tkt.endtime", offset(x.Tkt.EndTime, base))
	f.set("tkt.renew-till", offset(x.Tkt.RenewTill, base))
	f.set("tkt.caddr", rawField(x.Tkt.CAddr))
	f.set("tkt.authz-data", authzField(x.Tkt))
}

// authzField renders a ticket's authorization data by its *shape*
// rather than by its length.
//
// Until E3 nothing put authorization data in a ticket, so this field
// was a length on both sides and compared the absence of one. Now
// every ticket carries a PAC, and a length comparison would pass two
// PACs whose buffers were in different orders or whose CLIENT_INFO
// named different clients in the same number of octets -- which is
// the same failure mode the transited field's comment above
// describes.
func authzField(t wire.EncTicketPart) string {
	if len(t.AuthorizationData.FullBytes) == 0 {
		return absent
	}
	ad, err := wire.AuthDataOf(t.AuthorizationData)
	if err != nil {
		return fmt.Sprintf("<unparseable: %v>", err)
	}
	return authzShape(ad)
}

func normalizeEnc(
	f *Fields,
	x Exchange,
	realm string,
	base time.Time,
) {
	e := x.Enc
	f.set("enc.key", keySummary(e.Key))
	f.set("enc.last-req", lastReqSummary(e.LastReq))
	f.set("enc.nonce", "<nonce>")
	f.set("enc.key-expiration", offset(e.KeyExpiration, base))
	f.set("enc.flags", flagNames(e.Flags))
	f.set("enc.authtime", "base")
	f.set("enc.starttime", offset(e.StartTime, base))
	f.set("enc.endtime", offset(e.EndTime, base))
	f.set("enc.renew-till", offset(e.RenewTill, base))
	f.set("enc.srealm", scrub(e.SRealm, realm))
	f.set("enc.sname", scrubName(e.SName, realm))
	f.set("enc.caddr", rawField(e.CAddr))
	f.set("enc.enc-padata", padataSummary(e.EncPAData))
}

// offset renders a timestamp relative to the exchange's authtime.
//
// Absolute times cannot be compared: krb5kdc -T takes a relative
// offset rather than an absolute clock pin and there is no
// absolute-time hook anywhere in the tree, and kdc_timesync is on by
// default so a client adopts the KDC's clock after its first reply.
// The differences between the times are what the KDC actually
// decided, so those are what is compared.
func offset(t, base time.Time) string {
	if t.IsZero() {
		return absent
	}
	return fmt.Sprintf("base%+d", int64(t.Sub(base)/time.Second))
}

// encSummary describes a ciphertext without its bytes. The length is
// kept because it is deterministic: AES-CTS is length-preserving, so
// header plus plaintext plus trailer is exact.
func encSummary(e wire.EncryptedData) string {
	return fmt.Sprintf("<enc:etype=%d,kvno=%d,len=%d>",
		e.EType, e.KVNO, len(e.Cipher))
}

func keySummary(k wire.EncryptionKey) string {
	return fmt.Sprintf("<key:etype=%d,len=%d>",
		k.KeyType, len(k.KeyValue))
}

func lastReqSummary(es []wire.LastReqEntry) string {
	if len(es) == 0 {
		return absent
	}
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = fmt.Sprintf("type=%d,at=%d",
			e.Type, e.Value.Unix())
	}
	return strings.Join(parts, " ")
}

func padataSummary(ps []wire.PAData) string {
	if len(ps) == 0 {
		return absent
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		if p.Type == wire.PAFXFast && len(p.Value) > 0 {
			parts[i] = "type=136,len=<fast>"
			continue
		}
		parts[i] = fmt.Sprintf("type=%d,len=%d",
			p.Type, len(p.Value))
	}
	return strings.Join(parts, " ")
}

// A non-empty PA-FX-FAST is the one padata element whose length is
// not deterministic, and it is elided for that reason alone -- every
// other element's length is still compared, including an *empty*
// PA-FX-FAST, which is the advertisement and whose length is always
// nought.
//
// The reason is one field. A KrbFastResponse's finished part carries
// a microsecond count as a DER INTEGER, whose width is one to three
// octets depending on the value, so the ciphertext around it changes
// length with the clock. Observed directly: five runs of the armored
// TGS comparison gave the C KDC 199, 199, 199, 199 and then 198
// octets for the same exchange. Every other ciphertext in this
// harness has a deterministic length -- only the confounder inside it
// varies -- which is why comparing lengths is worth doing at all and
// why this exception needs naming rather than a blanket elision.

// rawField renders a field this harness carries as opaque DER.
//
// The context tag is part of the rendering and not only the length,
// because the same bytes under the wrong tag is a real failure mode
// here and a silent one: the request body's addresses are [9] and an
// EncKDCRepPart's are [11], the two are otherwise identical, and a
// decoder that meets an unexpected tag treats it as the end of the
// sequence rather than complaining (k5_asn1_decode_sequence,
// lib/krb5/asn.1/asn1_encode.c). A client would then see no addresses
// and no encrypted padata either, and say nothing.
func rawField(v asn1.RawValue) string {
	if len(v.FullBytes) == 0 {
		return absent
	}
	return fmt.Sprintf("<der:[%d],len=%d>",
		v.Tag, len(v.FullBytes))
}

// scrub replaces the realm with a placeholder, so that a harness run
// against a differently named realm still compares.
func scrub(s, realm string) string {
	if s == "" {
		return absent
	}
	return strings.ReplaceAll(s, realm, "<realm>")
}

func scrubName(p wire.PrincipalName, realm string) string {
	return fmt.Sprintf("type=%d %s", p.Type,
		scrub(p.String(), realm))
}

// flagNames renders ticket flags by name, in bit order.
//
// By name rather than as a hex word on purpose: a one-bit difference
// in 0xFEDCBA98 is invisible in a failure message, and the bit
// numbering is the single most error-prone part of the protocol.
func flagNames(f wire.Flags) string {
	named := []struct {
		name string
		flag wire.Flags
	}{
		{"reserved", wire.FlagReserved},
		{"forwardable", wire.FlagForwardable},
		{"forwarded", wire.FlagForwarded},
		{"proxiable", wire.FlagProxiable},
		{"proxy", wire.FlagProxy},
		{"may-postdate", wire.FlagMayPostdate},
		{"postdated", wire.FlagPostdated},
		{"invalid", wire.FlagInvalid},
		{"renewable", wire.FlagRenewable},
		{"initial", wire.FlagInitial},
		{"pre-authent", wire.FlagPreAuthent},
		{"hw-authent", wire.FlagHWAuthent},
		{"transited-policy-checked",
			wire.FlagTransitedPolicyChecked},
		{"ok-as-delegate", wire.FlagOKAsDelegate},
		{"enc-pa-rep", wire.FlagEncPARep},
		{"anonymous", wire.FlagAnonymous},
	}
	var set []string
	for _, n := range named {
		if f.Has(n.flag) {
			set = append(set, n.name)
		}
	}
	if len(set) == 0 {
		return "<none>"
	}
	return strings.Join(set, " ")
}
