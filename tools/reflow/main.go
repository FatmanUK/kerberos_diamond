// Command reflow rewraps Go line comments to a column limit.
//
// gofmt does not wrap anything, and golines wraps code but shortens
// comments a line at a time, which leaves orphans like "// the ones
// that" rather than reflowing the paragraph. This does the paragraph.
//
//	go run ./tools/reflow -w ./internal/...
//	go run ./tools/reflow -l .   # list what would change
//
// A comment is reflowed only when the whole paragraph is plain prose.
// Anything that carries its own layout is left exactly as written:
// indented examples, list items, table rows, directives, and any
// paragraph holding a word too long to fit.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxCols is the column limit, counting a tab as tabWidth columns.
const (
	maxCols  = 70
	tabWidth = 8
)

func main() {
	write := flag.Bool("w", false, "rewrite files in place")
	list := flag.Bool("l", false, "list files that would change")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(
			os.Stderr,
			"usage: reflow [-w] [-l] <path>...",
		)
		os.Exit(2)
	}

	var changed []string
	for _, root := range flag.Args() {
		files, err := goFiles(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reflow:", err)
			os.Exit(1)
		}
		for _, path := range files {
			ok, err := process(path, *write)
			if err != nil {
				fmt.Fprintln(
					os.Stderr,
					"reflow:",
					err,
				)
				os.Exit(1)
			}
			if ok {
				changed = append(changed, path)
			}
		}
	}

	if *list {
		for _, p := range changed {
			fmt.Println(p)
		}
	}
	// Listing is a check: a non-empty list means the tree is not
	// formatted, which a CI job wants to fail on.
	if *list && len(changed) > 0 {
		os.Exit(1)
	}
}

// goFiles collects the .go files under root, skipping the vendored C
// submodule and anything generated.
func goFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(
		root,
		func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// kerberos/ is upstream's C,
				// read-only reference.
				if d.Name() == "kerberos" ||
					d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			// Generated files are the generators'
			// business; narrowing them there is what
			// keeps "go generate" from undoing this.
			if strings.HasSuffix(p, "_gen.go") {
				return nil
			}
			out = append(out, p)
			return nil
		},
	)
	return out, err
}

// process reflows one file, reporting whether it changed.
func process(path string, write bool) (bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	out := reflow(src)
	if bytes.Equal(src, out) {
		return false, nil
	}
	if write {
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		err = os.WriteFile(path, out, info.Mode())
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// splitOneLiners puts the body of an over-long one-line function
// declaration on its own line.
//
// This runs before any code-wrapping tool, and the order matters.
// Given a declaration whose body is what pushes it past the limit —
// a method with a receiver, two parameters, two results and a
// one-expression body — golines would split the *parameter list*,
// one parameter per line, because that is the only thing it knows how
// to break. Moving the body out first leaves a signature of fifty
// columns, which it then leaves alone, and the result is what anyone
// would have written by hand.
//
// The example is described rather than shown because showing it would
// mean writing a line this tool exists to prevent.
func splitOneLiners(lines []string) []string {
	var out []string
	for _, line := range lines {
		open, body, ok := oneLineFunc(line)
		if !ok || visualWidth(line) <= maxCols {
			out = append(out, line)
			continue
		}
		bare := strings.TrimLeft(line, " \t")
		indent := line[:len(line)-len(bare)]
		out = append(out, open, indent+"\t"+body, indent+"}")
	}
	return out
}

// oneLineFunc splits "func f() { body }" into its opening line and
// its body, reporting whether the line has that shape at all.
//
// The scan tracks strings and runes so a brace inside either is not
// mistaken for the one opening the body, and requires the body's own
// braces to balance — anything stranger is left alone rather than
// guessed at.
func oneLineFunc(line string) (open, body string, ok bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, "func ") ||
		!strings.HasSuffix(trimmed, "}") {
		return "", "", false
	}

	// depth counts () and [] nesting, so that the braces of a
	// func type are not mistaken for a body.
	depth := 0
	braces := 0 // {} nesting
	start := -1 // index just past the brace opening the body
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '{':
			if depth == 0 && braces == 0 {
				start = i + 1
			}
			braces++
		case '}':
			braces--
		}
	}
	// A body that never opened, never closed, or holds no
	// statement is not this transformation's business.
	if start < 0 || braces != 0 || quote != 0 ||
		start >= len(line)-1 {
		return "", "", false
	}
	body = strings.TrimSpace(line[start : len(line)-1])
	if body == "" {
		return "", "", false
	}
	return strings.TrimRight(line[:start], " \t"), body, true
}

// splitFields puts each field of an over-long composite literal on
// its own line.
//
//	Name: m.Name, Definition: m.Definition, Owner: int32(m.Owner),
//
// becomes one field per line, which gofmt then aligns on the colons.
// Only a line whose every piece is "key: value" is touched, so an
// ordinary comma-separated expression is left alone.
func splitFields(lines []string) []string {
	var out []string
	for _, line := range lines {
		fields, ok := literalFields(line)
		if !ok || visualWidth(line) <= maxCols {
			out = append(out, line)
			continue
		}
		indent := leading(line)
		for _, f := range fields {
			out = append(out, indent+f+",")
		}
	}
	return out
}

// literalFields splits a trailing-comma line into its "key: value"
// pieces, reporting whether every piece has that shape.
func literalFields(line string) ([]string, bool) {
	body := strings.TrimSpace(line)
	if !strings.HasSuffix(body, ",") {
		return nil, false
	}
	pieces := splitTopLevel(strings.TrimSuffix(body, ","))
	if len(pieces) < 2 {
		return nil, false
	}
	for _, p := range pieces {
		key, _, found := strings.Cut(p, ":")
		if !found || !isIdent(strings.TrimSpace(key)) {
			return nil, false
		}
	}
	return pieces, true
}

// splitBools breaks an over-long condition after its && or ||
// operators.
//
// Go's own style breaks after the operator, so the continuation reads
// as obviously unfinished; gofmt then indents it.
func splitBools(lines []string) []string {
	var out []string
	for _, line := range lines {
		if visualWidth(line) <= maxCols {
			out = append(out, line)
			continue
		}
		body := strings.TrimSpace(line)
		keyword := body == "" ||
			strings.HasPrefix(body, "if ") ||
			strings.HasPrefix(body, "for ") ||
			strings.HasPrefix(body, "} else if ")
		if !keyword {
			out = append(out, line)
			continue
		}
		parts := splitOperators(line)
		if len(parts) < 2 {
			out = append(out, line)
			continue
		}
		packed := packOperands(parts, leading(line))
		out = append(out, packed...)
	}
	return out
}

// packOperands puts as many operands on each line as fit, rather than
// one per line: a condition broken at every operator reads as a
// column of fragments, where the point of breaking it was to keep it
// legible.
func packOperands(parts []string, indent string) []string {
	var out []string
	cont := indent + "\t"

	line := parts[0]
	for _, p := range parts[1:] {
		joined := line + " " + p
		// The first line carries the keyword and so is
		// measured as it stands; a continuation is measured
		// with its indent.
		width := visualWidth(joined)
		if len(out) > 0 {
			width = visualWidth(cont + joined)
		}
		if width <= maxCols {
			line = joined
			continue
		}
		if len(out) == 0 {
			out = append(out, line)
		} else {
			out = append(out, cont+line)
		}
		line = p
	}
	if len(out) == 0 {
		return []string{line}
	}
	return append(out, cont+line)
}

// splitOperators cuts a line after each top-level && or ||, keeping
// the operator on the line it ends.
func splitOperators(line string) []string {
	var parts []string
	start, depth := 0, 0
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '&', '|':
			if depth != 0 || i+1 >= len(line) ||
				line[i+1] != c {
				continue
			}
			part := line[start : i+2]
			parts = append(parts,
				strings.TrimRight(part, " "))
			start = i + 2
			i++
		}
	}
	if start == 0 {
		return nil
	}
	// A condition already broken across lines ends with its
	// operator, so the tail is empty. Emitting it would add a
	// blank line on every run, which is both noise and a failure
	// to be idempotent.
	if tail := strings.TrimSpace(line[start:]); tail != "" {
		parts = append(parts, tail)
	}
	if len(parts) < 2 {
		return nil
	}
	return parts
}

// splitTopLevel cuts a string at commas that are not nested inside
// brackets or a string literal.
func splitTopLevel(s string) []string {
	var out []string
	start, depth := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out,
					strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// leading returns a line's indentation.
func leading(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// isIdent reports whether s is a plain Go identifier, which is what a
// composite literal's field key must be.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' ||
			c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			i > 0 && c >= '0' && c <= '9'
		if !ok {
			return false
		}
	}
	return true
}

// reflow rewraps every eligible comment paragraph in a file, and
// restructures the code shapes that a line-wrapper cannot reach.
func reflow(src []byte) []byte {
	lines := strings.Split(string(src), "\n")
	lines = splitOneLiners(lines)
	lines = splitFields(lines)
	lines = splitBools(lines)
	var out []string

	for i := 0; i < len(lines); {
		indent, _, ok := commentParts(lines[i])
		if !ok {
			out = append(out, lines[i])
			i++
			continue
		}

		// Gather the run of comment lines sharing this
		// indentation.
		j := i
		for j < len(lines) {
			ind, _, ok := commentParts(lines[j])
			if !ok || ind != indent {
				break
			}
			j++
		}
		out = append(out, reflowRun(lines[i:j], indent)...)
		i = j
	}
	return []byte(strings.Join(out, "\n"))
}

// commentParts splits a line into its leading whitespace and the text
// after "//", reporting whether it is a line comment at all.
func commentParts(line string) (indent, text string, ok bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, "//") {
		return "", "", false
	}
	indent = line[:len(line)-len(trimmed)]
	return indent, strings.TrimPrefix(trimmed, "//"), true
}

// reflowRun rewraps one run of same-indent comment lines, paragraph
// by paragraph. A blank comment line separates paragraphs and is
// kept.
func reflowRun(run []string, indent string) []string {
	var out []string
	var para []string

	flush := func() {
		if len(para) > 0 {
			out = append(
				out,
				wrapParagraph(para, indent)...)
			para = nil
		}
	}

	for _, line := range run {
		_, text, _ := commentParts(line)
		if strings.TrimSpace(text) == "" {
			flush()
			out = append(out, line)
			continue
		}
		para = append(para, text)
	}
	flush()
	return out
}

// wrapParagraph rewraps one paragraph, or returns it untouched when
// it is not plain prose.
func wrapParagraph(para []string, indent string) []string {
	if !reflowable(para) {
		return rebuild(para, indent)
	}

	width := maxCols - visualWidth(indent) - len("// ")
	if width < 20 {
		// Too deeply indented to wrap sensibly; leave it be
		// rather than produce a column of single words.
		return rebuild(para, indent)
	}

	var words []string
	for _, line := range para {
		words = append(words, strings.Fields(line)...)
	}
	if len(words) == 0 {
		return rebuild(para, indent)
	}

	var out []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) <= width {
			line += " " + w
			continue
		}
		out = append(out, indent+"// "+line)
		line = w
	}
	return append(out, indent+"// "+line)
}

// rebuild returns a paragraph exactly as it was written.
func rebuild(para []string, indent string) []string {
	out := make([]string, len(para))
	for i, text := range para {
		out[i] = strings.TrimRight(indent+"//"+text, " \t")
	}
	return out
}

// reflowable reports whether a paragraph is plain prose that may be
// rewrapped.
//
// Anything carrying its own layout is refused, because rewrapping
// would destroy it: an indented example, a list, a table, a
// directive. A paragraph holding a word longer than the available
// width is refused too — wrapping cannot help it, and trying
// produces a ragged mess around the long token.
func reflowable(para []string) bool {
	for i, text := range para {
		switch {
		case text == "":
			return false
		// A directive such as //go:generate must stay on its
		// own line, exactly as written.
		case !strings.HasPrefix(text, " "):
			return false
		// An indented line inside a comment is a code block
		// in Go's own doc convention.
		case strings.HasPrefix(text, "\t"),
			strings.HasPrefix(text, "  "):
			return false
		}

		body := strings.TrimSpace(text)
		switch {
		// Lists and tables carry their shape in the leading
		// character.
		case strings.HasPrefix(body, "- "),
			strings.HasPrefix(body, "* "):
			return false
		case strings.HasPrefix(body, "|"),
			strings.HasSuffix(body, "|"):
			return false
		// A numbered list item, "1." or "1)".
		case numbered(body):
			return false
		}

		// Only the first line may introduce the paragraph; a
		// later line starting a list means the paragraph is
		// really several.
		_ = i
	}
	return true
}

// numbered reports whether a line opens with "12." or "12)".
func numbered(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(s) {
		return false
	}
	return s[i] == '.' || s[i] == ')'
}

// visualWidth is how many columns a run of leading whitespace
// occupies, counting a tab as tabWidth.
func visualWidth(indent string) int {
	n := 0
	for _, r := range indent {
		if r == '\t' {
			n += tabWidth - (n % tabWidth)
			continue
		}
		n++
	}
	return n
}
