// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func TestXMLAttribures(t *testing.T) {
	xmldoc := `<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry <bold>Potter</bold> Biography</title>
  <price secret="value">29.99</price>
</book>

<book>
  <title lang="en">Learning XML</title>
  <price>39.95</price>
</book>

</bookstore>`
	attrs, contents, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
	if err != nil {
		t.Error(err)
	}
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}
	if len(contents) != 6 {
		t.Errorf("Expected 6 contents, got %d", len(contents))
	}
	eattrs := []string{"en", "value"}
	econtent := []string{"Harry", "Potter", "Biography", "29.99", "Learning XML", "39.95"}
	for _, attr := range eattrs {
		if !strings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !strings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
}

func TestXMLPayloadFlexibility(t *testing.T) {
	xmldoc := `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget me this weekend!
		</note>`
	_, contents, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
	if err != nil {
		t.Error(err)
	}
	for _, content := range []string{"Tove", "Jani", "Reminder", "Don't forget me this weekend!"} {
		if !strings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
	if len(contents) != 4 {
		t.Errorf("Expected 4 contents, got %d", len(contents))
	}
}

// Elements named after HTML void elements are ordinary containers in XML
// vocabularies, and their end tag must not abort decoding.
func TestXMLHTMLVoidElementNames(t *testing.T) {
	testCases := []struct {
		Name  string
		Input string
		Want  []string
	}{
		{
			Name: "xmlRPCGetUsersBlogs",
			Input: `<?xml version="1.0"?>
			<methodCall>
			  <methodName>wp.getUsersBlogs</methodName>
			  <params>
				<param><value><string>admin</string></value></param>
				<param><value><string>hunter2</string></value></param>
			  </params>
			</methodCall>`,
			Want: []string{"wp.getUsersBlogs", "admin", "hunter2"},
		},
		{
			Name: "xmlRPCMulticall",
			Input: `<?xml version="1.0"?>
			<methodCall>
			  <methodName>system.multicall</methodName>
			  <params><param><value><array><data>
				<value><struct>
				  <member><name>methodName</name><value><string>wp.getCategories</string></value></member>
				</struct></value>
			  </data></array></value></param></params>
			</methodCall>`,
			Want: []string{"system.multicall", "methodName", "wp.getCategories"},
		},
		{
			Name:  "atomLink",
			Input: `<entry><link href="https://example.com">alternate</link></entry>`,
			Want:  []string{"alternate"},
		},
		{
			// Elements left unterminated still decode, so leniency for
			// unbalanced documents does not depend on self-closing them.
			Name:  "unterminatedParam",
			Input: `<methodCall><params><param><value>admin</value></params></methodCall>`,
			Want:  []string{"admin"},
		},
		{
			Name:  "unterminatedHTMLVoidElements",
			Input: `<html><body>before<br>after<img src="x"></body></html>`,
			Want:  []string{"before", "after"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, contents, err := readXML(bytes.NewReader([]byte(tc.Input)), 0)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := len(contents), len(tc.Want); got != want {
				t.Fatalf("contents count mismatch, got=%d (%v), want=%d", got, contents, want)
			}
			for i := range contents {
				if got, want := contents[i], tc.Want[i]; got != want {
					t.Errorf("Expected content got=%s, want=%s", got, want)
				}
			}
		})
	}
}

func TestXMLUnexpectedEOF(t *testing.T) {
	testCases := []struct {
		Name  string
		Input string
		Want  []string
	}{
		{
			Name: "inTheMiddleOfText",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget`,
			Want: []string{"Tove", "Jani", "Reminder", "Don't forget"},
		},
		{
			Name: "inTheMiddleOfStartElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<bod`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
		{
			Name: "inTheMiddleOfEndElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			xmldoc := tc.Input
			_, contents, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
			if err != nil {
				t.Error(err)
			}
			if got, want := len(contents), len(tc.Want); got != want {
				t.Errorf("contents count mismatch, got=%d, want=%d", got, want)
			}
			for i := range min(len(contents), len(tc.Want)) {
				if got, want := contents[i], tc.Want[i]; got != want {
					t.Errorf("Expected content got=%s, want=%s", got, want)
				}
			}
		})
	}
}
