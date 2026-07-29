package token

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
)

// linkRelID is the relationship id the document body uses to reach the external
// image. Any id works as long as the two parts agree; a high number keeps it
// clear of the hand-written rId1 the package relationship uses.
const linkRelID = "rId1000"

// Docx renders a Word document that fires the token when it is opened.
//
// The mechanism is a linked — not embedded — image. OOXML lets a picture point
// at an external target with TargetMode="External", and Word resolves that
// target over the network when it lays the document out. So the moment the file
// is opened, Word fetches the callback URL and the token fires; the console
// answers with a 1x1 image, and nothing about the document looks unusual.
//
// This is the one token that reaches an intruder who never touches the network
// the sensors watch: the document can be carried off a share, mailed onward,
// dropped in a personal cloud drive, and it still calls home from wherever it
// is finally opened.
func Docx(cfg Config, id string) ([]byte, error) {
	target, err := HTTPURL(cfg, id)
	if err != nil {
		return nil, err
	}

	parts := []struct {
		name string
		body string
	}{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", packageRelsXML},
		{"word/document.xml", documentXML},
		{"word/_rels/document.xml.rels", documentRelsXML(target)},
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		// Store rather than Deflate on the tiny parts is not worth the
		// complexity; the default (Deflate) is fine and produces a smaller file.
		w, err := zw.Create(p.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const packageRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

// documentRelsXML maps the body's linked image to the callback URL. TargetMode
// "External" is the whole trick: Word fetches the target instead of expecting
// the bytes to be inside the package.
func documentRelsXML(target string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="` + linkRelID + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="` + xmlAttr(target) + `" TargetMode="External"/>
</Relationships>`
}

// documentXML is a one-line document carrying a linked picture. The visible
// text is deliberately bland: the file is meant to be renamed to whatever suits
// where it is planted, and a blank page would look more suspicious than a dull
// sentence.
const documentXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:body>
    <w:p>
      <w:r><w:t xml:space="preserve">This document is confidential and for internal use only.</w:t></w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:drawing>
          <wp:inline distT="0" distB="0" distL="0" distR="0">
            <wp:extent cx="990600" cy="1122363"/>
            <wp:effectExtent l="0" t="0" r="0" b="0"/>
            <wp:docPr id="1" name="Picture 1"/>
            <wp:cNvGraphicFramePr>
              <a:graphicFrameLocks noChangeAspect="1"/>
            </wp:cNvGraphicFramePr>
            <a:graphic>
              <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
                <pic:pic>
                  <pic:nvPicPr>
                    <pic:cNvPr id="1" name="Picture 1"/>
                    <pic:cNvPicPr/>
                  </pic:nvPicPr>
                  <pic:blipFill>
                    <a:blip r:link="` + linkRelID + `"/>
                    <a:stretch><a:fillRect/></a:stretch>
                  </pic:blipFill>
                  <pic:spPr>
                    <a:xfrm><a:off x="0" y="0"/><a:ext cx="990600" cy="1122363"/></a:xfrm>
                    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                  </pic:spPr>
                </pic:pic>
              </a:graphicData>
            </a:graphic>
          </wp:inline>
        </w:drawing>
      </w:r>
    </w:p>
  </w:body>
</w:document>`

// xmlAttr escapes s for use inside a double-quoted XML attribute — the callback
// URL goes into the relationship's Target, and an unescaped & there is a
// corrupt document.
func xmlAttr(s string) string {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		// EscapeText only fails if the writer fails, and a bytes.Buffer does not.
		return s
	}
	return b.String()
}

// gifPixel is the 1x1 transparent GIF the console answers a token callback
// with, so a linked image in a document resolves to something valid and the
// fetch leaves no visible trace. It lives here beside the document that expects
// an image to come back.
var gifPixel = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// GIFPixel returns a copy of the 1x1 GIF used to answer image callbacks.
func GIFPixel() []byte {
	out := make([]byte, len(gifPixel))
	copy(out, gifPixel)
	return out
}
