package attest

import (
	"os"
	"testing"
)

// The report is from a live Tinfoil enclave (key-transfer-probe kt-a, 2026-11-07),
// and the want is what xxd read at offset 0x1A0 of it.
func TestChipIDReadsTheReport(t *testing.T) {
	doc, err := os.ReadFile("testdata/kt-a-report.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ChipID(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := "1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44"
	if got != want {
		t.Fatalf("ChipID = %s\nwant      %s", got, want)
	}
	if _, err := ChipID([]byte(`{"cpu_evidence":{"report_base64":"AAAA"}}`)); err == nil {
		t.Fatal("read a CHIP_ID from a 3-byte report")
	}
}
