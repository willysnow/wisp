package token

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// readDocxPart returns one part of a generated .docx.
func readDocxPart(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	t.Fatalf("docx is missing part %q", name)
	return ""
}

// TestDocxIsAWellFormedPackage checks the file opens as a zip and carries the
// four parts Word needs to treat it as a document. A malformed package is one
// Word refuses to open, and a token that never opens never fires.
func TestDocxIsAWellFormedPackage(t *testing.T) {
	data, err := Docx(Config{BaseURL: testBase}, "abc123")
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}

	for _, part := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"word/document.xml",
		"word/_rels/document.xml.rels",
	} {
		body := readDocxPart(t, data, part)
		// Every part is XML; a part that does not parse is a corrupt document.
		if err := xml.Unmarshal([]byte(body), new(struct {
			XMLName xml.Name
		})); err != nil {
			t.Errorf("part %s is not well-formed XML: %v", part, err)
		}
	}
}

// TestDocxLinksTheCallbackURL is the load-bearing property: the document has an
// external image relationship pointing at the token's callback URL, which is
// what Word fetches on open. Without TargetMode="External" Word looks for the
// bytes inside the package and never reaches the network.
func TestDocxLinksTheCallbackURL(t *testing.T) {
	data, err := Docx(Config{BaseURL: testBase}, "abc123")
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}

	rels := readDocxPart(t, data, "word/_rels/document.xml.rels")
	if !strings.Contains(rels, testBase+"/t/abc123") {
		t.Errorf("relationships do not target the callback URL:\n%s", rels)
	}
	if !strings.Contains(rels, `TargetMode="External"`) {
		t.Errorf("image relationship is not external, so Word would not fetch it:\n%s", rels)
	}

	// The body must reference the same relationship id, or the linked image is
	// declared but never placed and nothing is fetched.
	doc := readDocxPart(t, data, "word/document.xml")
	if !strings.Contains(doc, linkRelID) {
		t.Errorf("document body does not reference the linked image %s:\n%s", linkRelID, doc)
	}
}

// TestDocxEscapesURL guards the one place attacker- or config-supplied text
// enters raw XML: an unescaped & in the Target makes a corrupt document that
// Word will not open, taking the token with it.
func TestDocxEscapesURL(t *testing.T) {
	data, err := Docx(Config{BaseURL: "https://c.example.com/a&b"}, "id")
	if err != nil {
		t.Fatalf("Docx: %v", err)
	}
	rels := readDocxPart(t, data, "word/_rels/document.xml.rels")
	if strings.Contains(rels, "a&b") {
		t.Errorf("raw & left in the relationship Target — corrupt XML:\n%s", rels)
	}
	if !strings.Contains(rels, "a&amp;b") {
		t.Errorf("URL & not escaped to &amp;:\n%s", rels)
	}
}

func TestGIFPixelIsAGIF(t *testing.T) {
	p := GIFPixel()
	if !bytes.HasPrefix(p, []byte("GIF89a")) {
		t.Errorf("pixel is not a GIF: % x", p[:6])
	}
	// A returned copy must not alias the package's own bytes, or a handler that
	// mutated it would corrupt every later response.
	p[0] = 0
	if GIFPixel()[0] == 0 {
		t.Error("GIFPixel returns a shared slice, not a copy")
	}
}
