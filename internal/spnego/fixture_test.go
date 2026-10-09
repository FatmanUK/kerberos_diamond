package spnego

import (
	"encoding/hex"
	"strings"
	"testing"
)

// realNegTokenInit is a NegTokenInit captured from upstream's own
// gss-client, run as `gss-client -spnego' from the oracle container
// against this project's acceptor.
//
// It is here for the reason every other reference encoding in this
// project is: a decoder tested only against its own encoder agrees
// with itself and proves nothing. Upstream's asn.1 suite has nothing
// for SPNEGO -- reference_encode.out covers the Kerberos types and
// stops -- so these octets were captured from a real GSS-API
// initiator rather than looked up.
//
// Three things in it decide what the tests below assert:
//
//   - the mechTypeList holds **exactly one** mechanism, krb5. A GSS
//     initiator offers what its credential supports, and in a
//     Kerberos-only build that is one OID. So AcceptIncomplete is
//     the ordinary case and RequestMIC is reached only by a client
//     that prefers something else first.
//   - reqFlags and mechListMIC are both **absent**. Two of the four
//     fields a NegTokenInit may carry never appear here, which is
//     why their absence is asserted rather than assumed.
//   - the AP-REQ inside carries ap-options 0x20000000,
//     mutual-required, which gss-client sets by default
//     (gss-client.c:684).
//
// The ciphertext in the ticket and the authenticator is whatever that
// run produced and means nothing; the framing around it is the
// fixture.
const realNegTokenInit = `
	6082023406062b0601050502a082022830820224a00d300b06092a8648
	86f712010202a28202110482020d6082020906092a864886f712010202
	01006e8201f8308201f4a003020105a10302010ea20703050020000000
	a382010b6182010730820103a003020105a10f1b0d4b4449414d4f4e44
	2e54455354a21a3018a003020103a111300f1b066b61646d696e1b0561
	646d696ea381ce3081cba003020114a103020101a281be0481bbd9e256
	6db7dc25fedd2c6925b54bda9a3a3195666b99c04db920005ddb26855e
	0143f2a11ddf87024c32404b131fda7f8d7a9f5cb637900f9e1468c4c8
	3f35da1b6d40dcf618b1277db352bff5c48ff32fb1f9cf21ff1b3b7d66
	63c5fabb4ab1dd6ffcb0ab132a8a9b83ccb2fa2a0998e321b4c2878c9a
	a6b319e06d9e48704cf80e9bdad4d2797cb08c68f73c6226227fb5259d
	de2264a6d31bae1427ca17269eef182abec9055cd79a1cbe5ecd0aef8a
	9e0de0db6049a40abca4a481cf3081cca003020112a281c40481c1646a
	dfd62727fe61d0f8c9914edc5e2ec74236b6792db03b5bdb68d2311fd5
	0e1247da80ba55865ef5473b101e72a8b5beb963173bee50e4a78b0e54
	8089f9e67ae50dfb6b944c97f64ca8b5f291e8b7aeaf6998f3f1c27fdb
	5ccf1eee601ec5d830a753403432dbfbf13c4928a3a7b00b831a39912d
	926a70ba298f18f37bbd8bbb86118cd88824e2fabfaf8164c7e72c9f57
	a749fd8e2c0199680087dbce187adff43280769a3c360373882c9c14af
	b904f5f0df73dfc2e6fc960f7c36d29de8
`

// realToken is the fixture with its line breaks removed.
func realToken(t *testing.T) []byte {
	t.Helper()
	s := strings.Join(strings.Fields(realNegTokenInit), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("the fixture is not hex: %v", err)
	}
	return b
}
