// ODeauth — 802.11 Deauth/Disassoc Lab
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, static, CGO disabled)
// OWL Security Tools — Batch 3 (Wireless). Authorized testing only.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "ODeauth"
const SUITE = "Owl Wireless Suite"
const TAGLINE = "802.11 Deauth/Disassoc Analyzer"
const SUBLINE = "Detect · Reason Codes · Sources · Victims · Micro-bursts · Grade"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const CATEGORY = "OWireless"
const MITRE = "T1498, T1499, T1557.002"

const BANNER = `
 ██████╗ ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
██║   ██║██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║
██║   ██║██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
╚██████╔╝██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	UN  = "\033[4m"        // underline
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit ODeauth", DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", CY))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), CY))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", CY))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================================
//  OWL shared core — formatting, grading, numeric + byte helpers
// ============================================================================

var startedAt = time.Now()

func appVersion() string { return VERSION }

// sectionHeader prints a colored section heading used by help/howto/report views.
func sectionHeader(s string) {
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

func subHeader(s string) { fmt.Println("  " + col("» "+s, CY+B)) }

func kvRow(k, v string) {
	fmt.Println("  " + col("│  ", CY) + col(pad(k, 20), GY) + col(v, W))
}

func bullet(s string) { fmt.Println("   " + col("•", CY) + " " + col(s, W)) }

func numbered(i int, s string) {
	fmt.Println("   " + col(fmt.Sprintf("%2d.", i), CY+B) + " " + col(s, W))
}

// hr draws a plain separator (no ANSI) for exported text reports.
func hr(w int) string { return strings.Repeat("-", w) }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
//  Grading engine (A+ .. F) based on a 0..100 posture/quality score.
// ---------------------------------------------------------------------------

func gradeFromScore(score float64) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 63:
		return "D"
	case score >= 60:
		return "D-"
	default:
		return "F"
	}
}

func gradeColor(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return GRN + B
	case strings.HasPrefix(g, "B"):
		return GRN
	case strings.HasPrefix(g, "C"):
		return YLW
	case strings.HasPrefix(g, "D"):
		return R
	default:
		return R + B
	}
}

func gradeLabel(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return "Excellent posture"
	case strings.HasPrefix(g, "B"):
		return "Good posture, minor gaps"
	case strings.HasPrefix(g, "C"):
		return "Fair, several weaknesses"
	case strings.HasPrefix(g, "D"):
		return "Poor, material exposure"
	default:
		return "Critical exposure"
	}
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical:
		return R + B
	case SevHigh:
		return R
	case SevMedium:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score >= 0.1:
		return SevLow
	default:
		return SevInfo
	}
}

// sarifLevel maps severity to SARIF result levels.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Numeric / statistics helpers
// ---------------------------------------------------------------------------

func meanF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddevF(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := meanF(xs)
	s := 0.0
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

func minF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func percentileF(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	idx := int(clamp(p/100.0*float64(len(cp)-1), 0, float64(len(cp)-1)) + 0.5)
	return cp[idx]
}

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ---------------------------------------------------------------------------
//  Byte reader with endian-aware helpers
// ---------------------------------------------------------------------------

type byteReader struct {
	b   []byte
	pos int
	le  bool
}

func newReader(b []byte, le bool) *byteReader { return &byteReader{b: b, le: le} }

func (r *byteReader) remaining() int { return len(r.b) - r.pos }
func (r *byteReader) eof() bool      { return r.pos >= len(r.b) }

func (r *byteReader) u8() (uint8, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	var v uint16
	if r.le {
		v = binary.LittleEndian.Uint16(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint16(r.b[r.pos:])
	}
	r.pos += 2
	return v, true
}

func (r *byteReader) u32() (uint32, bool) {
	if r.pos+4 > len(r.b) {
		return 0, false
	}
	var v uint32
	if r.le {
		v = binary.LittleEndian.Uint32(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint32(r.b[r.pos:])
	}
	r.pos += 4
	return v, true
}

func (r *byteReader) u64() (uint64, bool) {
	if r.pos+8 > len(r.b) {
		return 0, false
	}
	var v uint64
	if r.le {
		v = binary.LittleEndian.Uint64(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint64(r.b[r.pos:])
	}
	r.pos += 8
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

func (r *byteReader) skip(n int) bool {
	if r.pos+n > len(r.b) || n < 0 {
		return false
	}
	r.pos += n
	return true
}

func (r *byteReader) align(n int) {
	if n <= 1 {
		return
	}
	if m := r.pos % n; m != 0 {
		r.pos += n - m
	}
}

// ============================================================================
//  Hex dump loader — tolerant of xxd / tcpdump / wireshark / raw hex layouts
// ============================================================================

// parseHexDump extracts raw bytes from assorted textual hex representations.
// It strips offsets (leading "0000  "), ASCII side panes, 0x prefixes, commas
// and whitespace, then decodes the remaining hex nibbles.
func parseHexDump(s string) ([]byte, error) {
	var out []byte
	lines := strings.Split(s, "\n")
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		// Drop a trailing ASCII pane after 2+ spaces or a '|' guard.
		if i := strings.Index(ln, "  |"); i >= 0 {
			ln = ln[:i]
		}
		fields := strings.Fields(ln)
		// Heuristic: if first field looks like an offset (hex, len>=4, no more
		// hex pairs resembling it), drop it.
		if len(fields) > 1 && looksLikeOffset(fields[0]) {
			fields = fields[1:]
		}
		for _, f := range fields {
			f = strings.TrimPrefix(f, "0x")
			f = strings.TrimPrefix(f, "0X")
			f = strings.TrimSuffix(f, ",")
			f = strings.TrimSuffix(f, ":")
			f = strings.TrimSuffix(f, "h")
			if f == "" {
				continue
			}
			// a chunk may be a run of nibbles with colons (aa:bb:cc)
			f = strings.ReplaceAll(f, ":", "")
			f = strings.ReplaceAll(f, "-", "")
			if !isHexRun(f) {
				continue
			}
			if len(f)%2 == 1 {
				// odd nibble count — ignore trailing nibble gracefully
				f = f[:len(f)-1]
			}
			d, err := hex.DecodeString(f)
			if err != nil {
				continue
			}
			out = append(out, d...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no hex bytes recovered from input")
	}
	return out, nil
}

func looksLikeOffset(s string) bool {
	s = strings.TrimSuffix(s, ":")
	if len(s) < 4 {
		return false
	}
	return isHexRun(s)
}

func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexPreview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// hexDumpBlock returns a classic offset | hex | ascii dump for display.
func hexDumpBlock(b []byte, maxBytes int) string {
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "  %04x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", b[i])
			} else {
				sb.WriteString("   ")
			}
			if i-off == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" ")
		for i := off; i < end; i++ {
			c := b[i]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ============================================================================
//  MAC address utilities
// ============================================================================

func macStr(b []byte) string {
	if len(b) < 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func parseMAC(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")
	parts := strings.Split(s, ":")
	if len(parts) == 1 && len(s) == 12 {
		// bare 12-nibble form
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 6 {
			return nil, errors.New("invalid MAC")
		}
		return b, nil
	}
	if len(parts) != 6 {
		return nil, errors.New("invalid MAC format")
	}
	out := make([]byte, 6)
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// macIsBroadcast reports an all-FF address.
func macIsBroadcast(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for _, c := range b[:6] {
		if c != 0xff {
			return false
		}
	}
	return true
}

func macIsMulticast(b []byte) bool {
	return len(b) >= 1 && b[0]&0x01 == 0x01
}

// macIsLocallyAdministered detects the U/L bit → randomized / software MAC.
func macIsLocallyAdministered(b []byte) bool {
	return len(b) >= 1 && b[0]&0x02 == 0x02
}

// macRandomizationClass classifies a MAC's address type.
func macRandomizationClass(b []byte) string {
	if len(b) < 6 {
		return "invalid"
	}
	if macIsBroadcast(b) {
		return "broadcast"
	}
	if macIsMulticast(b) {
		return "multicast"
	}
	if macIsLocallyAdministered(b) {
		// Second nibble 2,6,A,E indicate randomized device identifiers.
		switch b[0] & 0x0f {
		case 0x02, 0x06, 0x0a, 0x0e:
			return "randomized"
		}
		return "locally-administered"
	}
	return "global-OUI"
}

func ouiKey(b []byte) string {
	if len(b) < 3 {
		return "000000"
	}
	return fmt.Sprintf("%02X%02X%02X", b[0], b[1], b[2])
}

// lookupVendor resolves the OUI (first 3 bytes) to a vendor name.
func lookupVendor(b []byte) string {
	if len(b) < 3 {
		return "Unknown"
	}
	if macIsBroadcast(b) {
		return "Broadcast"
	}
	if macRandomizationClass(b) == "randomized" {
		return "Randomized/Private"
	}
	if v, ok := ouiDB[ouiKey(b)]; ok {
		return v
	}
	return "Unknown"
}

// ouiDB — curated IEEE OUI → vendor prefixes commonly seen in wireless gear.
var ouiDB = map[string]string{
	"000C43": "Ralink", "001018": "Broadcom", "00037F": "Atheros",
	"000D93": "Apple", "001451": "Apple", "0017F2": "Apple",
	"001B63": "Apple", "0021E9": "Apple", "002332": "Apple",
	"3C0754": "Apple", "A4C361": "Apple", "F0DBF8": "Apple",
	"DC2B2A": "Apple", "88665A": "Apple", "A85C2C": "Apple",
	"001A11": "Google", "3C5AB4": "Google", "F4F5E8": "Google",
	"DA A1 19": "Google", "D4F547": "Google", "001FF3": "Apple",
	"F8E079": "Samsung", "5C0A5B": "Samsung", "B479A7": "Samsung",
	"0012FB": "Samsung", "002567": "Samsung", "386077": "Samsung",
	"001D0F": "TP-Link", "14CC20": "TP-Link", "50C7BF": "TP-Link",
	"A42BB0": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
	"001A2B": "Cisco", "00400B": "Cisco", "0024C4": "Cisco",
	"58971E": "Cisco", "6400F1": "Cisco", "00059A": "Cisco",
	"0018F3": "ASUSTek", "001BFC": "ASUSTek", "2C56DC": "ASUSTek",
	"50465D": "ASUSTek", "AC220B": "ASUSTek", "D850E6": "ASUSTek",
	"001195": "D-Link", "00265A": "D-Link", "1CBDB9": "D-Link",
	"002401": "D-Link", "C8BE19": "D-Link", "B8A386": "D-Link",
	"000FB5": "Netgear", "00223F": "Netgear", "100D7F": "Netgear",
	"20E52A": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
	"001601": "Buffalo", "00247E": "Ubiquiti", "0418D6": "Ubiquiti",
	"24A43C": "Ubiquiti", "68D79A": "Ubiquiti", "802AA8": "Ubiquiti",
	"FCECDA": "Ubiquiti", "74ACB9": "Ubiquiti", "B4FBE4": "Ubiquiti",
	"001346": "DLink", "0090A9": "Western Digital", "001C10": "Cisco-Linksys",
	"002369": "Cisco-Linksys", "C0C1C0": "Cisco-Linksys", "48F8B3": "Cisco-Linksys",
	"000625": "Linksys", "001217": "Cisco-Linksys", "0020A6": "Proxim",
	"001CDF": "Belkin", "08863B": "Belkin", "94103E": "Belkin",
	"B4750E": "Belkin", "001501": "Zyxel", "5C6A80": "Zyxel",
	"0013492": "Zyxel", "001349": "Zyxel", "FC3497": "Zyxel",
	"000393": "Apple", "0003AA": "Watlow", "009069": "Juniper",
	"2C6BF5": "Juniper", "3CE5A6": "Hangzhou", "0018E7": "Cameo",
	"001E58": "WistronNe", "001CF0": "D-Link", "001E2A": "Netgear",
	"00037A": "Taiyo", "001E8C": "ASUSTek", "0024B2": "Netgear",
	"0026F2": "Netgear", "E0469A": "Netgear", "C03F0E": "Netgear",
	"00904C": "Epigram", "ACF7F3": "Xiaomi", "286C07": "Xiaomi",
	"640980": "Xiaomi", "F8A45F": "Xiaomi", "742344": "Xiaomi",
	"4CB16C": "Huawei", "002568": "Huawei", "48435A": "Huawei",
	"5CA86A": "Huawei", "80B686": "Huawei", "E8CD2D": "Huawei",
	"001986": "Intel", "001F3B": "Intel", "0024D7": "Intel",
	"7C7A91": "Intel", "A0A8CD": "Intel", "E4A471": "Intel",
	"34E6D7": "Intel", "9CB6D0": "Intel", "5CE0C5": "Intel",
	"001DE1": "Intel", "00037B": "Dlink", "001B2F": "Netgear",
	"002275": "Belkin", "08BD43": "Netgear", "0C8268": "TP-Link",
	"3872C0": "CloudNet", "00156D": "Ubiquiti", "DC9FDB": "Ubiquiti",
	"44D9E7": "Ubiquiti", "788A20": "Ubiquiti", "F09FC2": "Ubiquiti",
	"0CB2B7": "Sonos", "5CAAFD": "Sonos", "949F3E": "Sonos",
	"B8E937": "Sonos", "347E5C": "Sonos", "F0F6C1": "Sonos",
	"001124": "Apple", "002608": "Apple", "0026BB": "Apple",
	"28CFE9": "Apple", "7CD1C3": "Apple", "9027E4": "Apple",
	"C82A14": "Apple", "E0ACCB": "Apple", "F0989D": "Apple",
	"40B395": "Apple", "6C4008": "Apple", "8866A5": "Apple",
}

// ============================================================================
//  CSV + file helpers
// ============================================================================

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }

func readCSVRecords(path string) ([][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	return r.ReadAll()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func atoiSafe(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

func atofSafe(s string) float64 {
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ============================================================================
//  PCAP / PCAPNG reader (classic libpcap + minimal pcapng EPB)
// ============================================================================

// Link-layer header types we care about.
const (
	DLT_NULL        = 0
	DLT_EN10MB      = 1
	DLT_IEEE802_11  = 105
	DLT_RADIOTAP    = 127
	DLT_PPI         = 192
	DLT_BLUETOOTH   = 201 // BLUETOOTH_HCI_H4_WITH_PHDR
	DLT_BLE_LL      = 251 // BLUETOOTH_LE_LL
	DLT_IEEE802154  = 195 // IEEE802_15_4_WITHFCS
	DLT_IEEE802154B = 230 // IEEE802_15_4_NOFCS
	DLT_NORDIC_BLE  = 272
)

type capPacket struct {
	TsSec    uint32
	TsUsec   uint32
	OrigLen  uint32
	Data     []byte
	LinkType int
	Index    int
}

func (p capPacket) Time() time.Time {
	return time.Unix(int64(p.TsSec), int64(p.TsUsec)*1000).UTC()
}

type capFile struct {
	LinkType int
	Packets  []capPacket
	Format   string
}

// loadCapture auto-detects pcap, pcapng or raw-hex and returns parsed packets.
func loadCapture(path string) (*capFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCaptureBytes(b)
}

func parseCaptureBytes(b []byte) (*capFile, error) {
	if len(b) < 4 {
		return nil, errors.New("file too small")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	switch magic {
	case 0x0a0d0d0a:
		return parsePcapng(b)
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return parsePcap(b)
	}
	return nil, errors.New("unrecognized capture magic (not pcap/pcapng)")
}

func parsePcap(b []byte) (*capFile, error) {
	if len(b) < 24 {
		return nil, errors.New("short pcap global header")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	var le bool
	var nano bool
	switch magic {
	case 0xa1b2c3d4:
		le = false
	case 0xd4c3b2a1:
		le = true
	case 0xa1b23c4d:
		le = false
		nano = true
	case 0x4d3cb2a1:
		le = true
		nano = true
	default:
		return nil, errors.New("bad pcap magic")
	}
	_ = nano
	ord := binary.ByteOrder(binary.BigEndian)
	if le {
		ord = binary.LittleEndian
	}
	linktype := int(ord.Uint32(b[20:24]))
	cf := &capFile{LinkType: linktype, Format: "pcap"}
	pos := 24
	idx := 0
	for pos+16 <= len(b) {
		tsSec := ord.Uint32(b[pos : pos+4])
		tsUsec := ord.Uint32(b[pos+4 : pos+8])
		caplen := ord.Uint32(b[pos+8 : pos+12])
		origlen := ord.Uint32(b[pos+12 : pos+16])
		pos += 16
		if caplen > 262144 || pos+int(caplen) > len(b) {
			break
		}
		data := make([]byte, caplen)
		copy(data, b[pos:pos+int(caplen)])
		pos += int(caplen)
		cf.Packets = append(cf.Packets, capPacket{
			TsSec: tsSec, TsUsec: tsUsec, OrigLen: origlen,
			Data: data, LinkType: linktype, Index: idx,
		})
		idx++
	}
	return cf, nil
}

func parsePcapng(b []byte) (*capFile, error) {
	cf := &capFile{Format: "pcapng"}
	pos := 0
	le := true
	linktype := DLT_EN10MB
	for pos+12 <= len(b) {
		btype := binary.LittleEndian.Uint32(b[pos : pos+4])
		blen := binary.LittleEndian.Uint32(b[pos+4 : pos+8])
		if btype == 0x0a0d0d0a {
			// SHB sets byte order via BOM
			if pos+12 <= len(b) {
				bom := binary.LittleEndian.Uint32(b[pos+8 : pos+12])
				le = bom == 0x1a2b3c4d
			}
		}
		if blen < 12 || pos+int(blen) > len(b) {
			break
		}
		ord := binary.ByteOrder(binary.LittleEndian)
		if !le {
			ord = binary.BigEndian
		}
		switch btype {
		case 0x00000001: // Interface Description Block
			if pos+10 <= len(b) {
				linktype = int(ord.Uint16(b[pos+8 : pos+10]))
				cf.LinkType = linktype
			}
		case 0x00000006: // Enhanced Packet Block
			if pos+28 <= len(b) {
				caplen := int(ord.Uint32(b[pos+20 : pos+24]))
				origlen := ord.Uint32(b[pos+24 : pos+28])
				dstart := pos + 28
				if caplen >= 0 && dstart+caplen <= len(b) && caplen < 262144 {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		case 0x00000003: // Simple Packet Block
			if pos+12 <= len(b) {
				origlen := ord.Uint32(b[pos+8 : pos+12])
				dstart := pos + 12
				caplen := int(blen) - 16
				if caplen > 0 && dstart+caplen <= len(b) {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		}
		pos += int(blen)
	}
	return cf, nil
}

// ============================================================================
//  Radiotap header parser (subset of the common present fields)
// ============================================================================

type radiotapInfo struct {
	Present    bool
	Length     int
	TSFT       uint64
	Flags      uint8
	Rate       float64 // Mbps
	ChannelMHz uint16
	ChanFlags  uint16
	SignalDBm  int8
	NoiseDBm   int8
	Antenna    uint8
	HasSignal  bool
	HasRate    bool
	HasChannel bool
	MCS        uint8
	HasMCS     bool
	BadFCS     bool
}

// present bit indices
const (
	rtTSFT      = 0
	rtFlags     = 1
	rtRate      = 2
	rtChannel   = 3
	rtFHSS      = 4
	rtDBmSignal = 5
	rtDBmNoise  = 6
	rtLockQual  = 7
	rtTxAtten   = 8
	rtDbTxAtten = 9
	rtDBmTxPow  = 10
	rtAntenna   = 11
	rtDBAnt     = 12
	rtDBAntNo   = 13
	rtMCS       = 19
)

func parseRadiotap(b []byte) (radiotapInfo, []byte) {
	var ri radiotapInfo
	if len(b) < 8 {
		return ri, b
	}
	// it_version(1) it_pad(1) it_len(2) it_present(4...)
	length := int(binary.LittleEndian.Uint16(b[2:4]))
	if length < 8 || length > len(b) {
		return ri, b
	}
	ri.Present = true
	ri.Length = length
	// collect present words (extended bit 31)
	var presents []uint32
	off := 4
	for {
		if off+4 > len(b) {
			break
		}
		p := binary.LittleEndian.Uint32(b[off : off+4])
		presents = append(presents, p)
		off += 4
		if p&(1<<31) == 0 {
			break
		}
	}
	r := newReader(b[:length], true)
	r.pos = off
	has := func(word, bit int) bool {
		if word >= len(presents) {
			return false
		}
		return presents[word]&(1<<uint(bit)) != 0
	}
	// Only parse first present word's common fields in order.
	if has(0, rtTSFT) {
		r.align(8)
		ri.TSFT, _ = r.u64()
	}
	if has(0, rtFlags) {
		v, _ := r.u8()
		ri.Flags = v
		if v&0x40 != 0 {
			ri.BadFCS = true
		}
	}
	if has(0, rtRate) {
		v, _ := r.u8()
		ri.Rate = float64(v) / 2.0
		ri.HasRate = true
	}
	if has(0, rtChannel) {
		r.align(2)
		f, _ := r.u16()
		fl, _ := r.u16()
		ri.ChannelMHz = f
		ri.ChanFlags = fl
		ri.HasChannel = true
	}
	if has(0, rtFHSS) {
		r.skip(2)
	}
	if has(0, rtDBmSignal) {
		v, _ := r.u8()
		ri.SignalDBm = int8(v)
		ri.HasSignal = true
	}
	if has(0, rtDBmNoise) {
		v, _ := r.u8()
		ri.NoiseDBm = int8(v)
	}
	if has(0, rtLockQual) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDbTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDBmTxPow) {
		r.skip(1)
	}
	if has(0, rtAntenna) {
		v, _ := r.u8()
		ri.Antenna = v
	}
	if has(0, rtMCS) {
		if known, ok := r.u8(); ok {
			_ = known
			r.skip(1)
			if mcs, ok2 := r.u8(); ok2 {
				ri.MCS = mcs
				ri.HasMCS = true
			}
		}
	}
	// payload is everything after the radiotap header
	if length <= len(b) {
		return ri, b[length:]
	}
	return ri, b
}

// ============================================================================
//  IEEE 802.11 MAC header dissector
// ============================================================================

const (
	TypeMgmt = 0
	TypeCtrl = 1
	TypeData = 2
)

// management subtypes
const (
	MgmtAssocReq    = 0
	MgmtAssocResp   = 1
	MgmtReassocReq  = 2
	MgmtReassocResp = 3
	MgmtProbeReq    = 4
	MgmtProbeResp   = 5
	MgmtBeacon      = 8
	MgmtATIM        = 9
	MgmtDisassoc    = 10
	MgmtAuth        = 11
	MgmtDeauth      = 12
	MgmtAction      = 13
)

type dot11Frame struct {
	Version   int
	Type      int
	Subtype   int
	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	Protected bool
	Order     bool
	Duration  uint16
	Addr1     []byte // RA / DA
	Addr2     []byte // TA / SA
	Addr3     []byte // BSSID / DA / SA
	Addr4     []byte
	SeqNum    int
	FragNum   int
	QoS       uint16
	HasQoS    bool
	Body      []byte // frame body after fixed header (mgmt: starts at fixed params)
	FCSValid  bool
	Raw       []byte
}

func parseDot11(b []byte) (*dot11Frame, error) {
	if len(b) < 10 {
		return nil, errors.New("frame too short for 802.11 header")
	}
	f := &dot11Frame{Raw: b}
	fc := binary.LittleEndian.Uint16(b[0:2])
	f.Version = int(fc & 0x3)
	f.Type = int((fc >> 2) & 0x3)
	f.Subtype = int((fc >> 4) & 0xf)
	f.ToDS = fc&0x0100 != 0
	f.FromDS = fc&0x0200 != 0
	f.MoreFrag = fc&0x0400 != 0
	f.Retry = fc&0x0800 != 0
	f.PwrMgmt = fc&0x1000 != 0
	f.MoreData = fc&0x2000 != 0
	f.Protected = fc&0x4000 != 0
	f.Order = fc&0x8000 != 0
	f.Duration = binary.LittleEndian.Uint16(b[2:4])
	// addr1 always present
	if len(b) >= 10 {
		f.Addr1 = b[4:10]
	}
	off := 10
	if f.Type == TypeCtrl {
		// control frames: variable; only addr1 (and maybe addr2) present
		if len(b) >= 16 {
			f.Addr2 = b[10:16]
		}
		return f, nil
	}
	if len(b) >= 16 {
		f.Addr2 = b[10:16]
		off = 16
	}
	if len(b) >= 22 {
		f.Addr3 = b[16:22]
		off = 22
	}
	if len(b) >= 24 {
		sc := binary.LittleEndian.Uint16(b[22:24])
		f.FragNum = int(sc & 0xf)
		f.SeqNum = int(sc >> 4)
		off = 24
	}
	// 4-address data frame
	if f.Type == TypeData && f.ToDS && f.FromDS {
		if len(b) >= 30 {
			f.Addr4 = b[24:30]
			off = 30
		}
	}
	// QoS data
	if f.Type == TypeData && (f.Subtype&0x08) != 0 {
		if len(b) >= off+2 {
			f.QoS = binary.LittleEndian.Uint16(b[off : off+2])
			f.HasQoS = true
			off += 2
		}
	}
	if off <= len(b) {
		f.Body = b[off:]
	}
	return f, nil
}

func (f *dot11Frame) typeName() string {
	switch f.Type {
	case TypeMgmt:
		return "Management"
	case TypeCtrl:
		return "Control"
	case TypeData:
		return "Data"
	}
	return "Reserved"
}

func (f *dot11Frame) subtypeName() string {
	if f.Type == TypeMgmt {
		switch f.Subtype {
		case MgmtAssocReq:
			return "Assoc Request"
		case MgmtAssocResp:
			return "Assoc Response"
		case MgmtReassocReq:
			return "Reassoc Request"
		case MgmtReassocResp:
			return "Reassoc Response"
		case MgmtProbeReq:
			return "Probe Request"
		case MgmtProbeResp:
			return "Probe Response"
		case MgmtBeacon:
			return "Beacon"
		case MgmtATIM:
			return "ATIM"
		case MgmtDisassoc:
			return "Disassociation"
		case MgmtAuth:
			return "Authentication"
		case MgmtDeauth:
			return "Deauthentication"
		case MgmtAction:
			return "Action"
		}
	}
	if f.Type == TypeData {
		if f.Subtype == 0 {
			return "Data"
		}
		if f.Subtype == 4 {
			return "Null"
		}
		if f.Subtype&0x08 != 0 {
			return "QoS Data"
		}
	}
	if f.Type == TypeCtrl {
		switch f.Subtype {
		case 8:
			return "Block Ack Req"
		case 9:
			return "Block Ack"
		case 11:
			return "RTS"
		case 12:
			return "CTS"
		case 13:
			return "ACK"
		}
	}
	return fmt.Sprintf("Subtype-%d", f.Subtype)
}

// bssid returns the best-effort BSSID depending on DS bits.
func (f *dot11Frame) bssid() []byte {
	switch {
	case f.Type == TypeMgmt:
		return f.Addr3
	case !f.ToDS && !f.FromDS:
		return f.Addr3
	case f.ToDS && !f.FromDS:
		return f.Addr1
	case !f.ToDS && f.FromDS:
		return f.Addr2
	default:
		return f.Addr3
	}
}

// ============================================================================
//  Information Element (tagged parameter) parsing
// ============================================================================

type infoElement struct {
	ID   int
	Len  int
	Data []byte
}

const (
	eidSSID      = 0
	eidRates     = 1
	eidDSParam   = 3
	eidTIM       = 5
	eidCountry   = 7
	eidERP       = 42
	eidHTCap     = 45
	eidRSN       = 48
	eidExtRates  = 50
	eidHTInfo    = 61
	eidRMEnabled = 70
	eidExtCap    = 127
	eidVHTCap    = 191
	eidVHTOp     = 192
	eidVendor    = 221
	eidExtension = 255
)

// parseIEs reads tag/len/value triples from a management-frame body offset.
func parseIEs(body []byte) []infoElement {
	var ies []infoElement
	pos := 0
	for pos+2 <= len(body) {
		id := int(body[pos])
		l := int(body[pos+1])
		pos += 2
		if pos+l > len(body) {
			break
		}
		data := body[pos : pos+l]
		ies = append(ies, infoElement{ID: id, Len: l, Data: data})
		pos += l
	}
	return ies
}

func findIE(ies []infoElement, id int) *infoElement {
	for i := range ies {
		if ies[i].ID == id {
			return &ies[i]
		}
	}
	return nil
}

func ieSSID(ies []infoElement) string {
	ie := findIE(ies, eidSSID)
	if ie == nil {
		return ""
	}
	if ie.Len == 0 {
		return "<hidden>"
	}
	s := string(ie.Data)
	// hidden SSIDs can be all-zero
	allZero := true
	for _, c := range ie.Data {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "<hidden>"
	}
	return sanitizeSSID(s)
}

func sanitizeSSID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			sb.WriteRune(r)
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	return sb.String()
}

func ieChannel(ies []infoElement) int {
	if ie := findIE(ies, eidDSParam); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	if ie := findIE(ies, eidHTInfo); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	return 0
}

func ieSupportedRates(ies []infoElement) []float64 {
	var rates []float64
	for _, id := range []int{eidRates, eidExtRates} {
		if ie := findIE(ies, id); ie != nil {
			for _, r := range ie.Data {
				rates = append(rates, float64(r&0x7f)/2.0)
			}
		}
	}
	return rates
}

// ============================================================================
//  RSN / WPA security parsing
// ============================================================================

type rsnInfo struct {
	Present     bool
	WPA1        bool
	WPA2        bool
	WPA3        bool
	GroupCipher string
	Pairwise    []string
	AKM         []string
	MFPCapable  bool
	MFPRequired bool
	PMKIDs      [][]byte
}

func cipherName(suite [4]byte) string {
	// OUI 00-0F-AC (RSN) / 00-50-F2 (WPA)
	t := suite[3]
	switch t {
	case 0:
		return "Use-Group"
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128"
	case 5:
		return "WEP-104"
	case 6:
		return "BIP-CMAC-128"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	}
	return fmt.Sprintf("cipher-%d", t)
}

func akmName(suite [4]byte) string {
	t := suite[3]
	switch t {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE"
	case 9:
		return "FT-SAE"
	case 11:
		return "802.1X-SuiteB"
	case 12:
		return "802.1X-SuiteB-192"
	case 18:
		return "OWE"
	}
	return fmt.Sprintf("akm-%d", t)
}

func parseRSN(ie *infoElement) rsnInfo {
	var ri rsnInfo
	if ie == nil || ie.Len < 2 {
		return ri
	}
	ri.Present = true
	ri.WPA2 = true
	d := ie.Data
	pos := 2 // version
	readSuite := func() ([4]byte, bool) {
		var s [4]byte
		if pos+4 > len(d) {
			return s, false
		}
		copy(s[:], d[pos:pos+4])
		pos += 4
		return s, true
	}
	if g, ok := readSuite(); ok {
		ri.GroupCipher = cipherName(g)
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				ri.Pairwise = append(ri.Pairwise, cipherName(s))
			}
		}
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				name := akmName(s)
				ri.AKM = append(ri.AKM, name)
				if name == "SAE" || name == "FT-SAE" {
					ri.WPA3 = true
				}
			}
		}
	}
	if pos+2 <= len(d) {
		caps := binary.LittleEndian.Uint16(d[pos : pos+2])
		pos += 2
		ri.MFPRequired = caps&0x0040 != 0
		ri.MFPCapable = caps&0x0080 != 0
		// PMKID count + list
		if pos+2 <= len(d) {
			pc := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
			pos += 2
			for i := 0; i < pc; i++ {
				if pos+16 <= len(d) {
					id := make([]byte, 16)
					copy(id, d[pos:pos+16])
					ri.PMKIDs = append(ri.PMKIDs, id)
					pos += 16
				}
			}
		}
	}
	return ri
}

// parseWPA1 handles the Microsoft WPA vendor IE (221, OUI 00-50-F2 type 1).
func parseWPA1(ies []infoElement) bool {
	for _, ie := range ies {
		if ie.ID == eidVendor && ie.Len >= 4 {
			if ie.Data[0] == 0x00 && ie.Data[1] == 0x50 && ie.Data[2] == 0xf2 && ie.Data[3] == 0x01 {
				return true
			}
		}
	}
	return false
}

// securityString summarises the privacy posture of a BSS.
func securityString(privacy bool, rsn rsnInfo, wpa1 bool) string {
	if rsn.WPA3 {
		if contains(rsn.AKM, "OWE") {
			return "OWE"
		}
		return "WPA3-SAE"
	}
	if rsn.Present {
		if contains(rsn.AKM, "802.1X") || contains(rsn.AKM, "802.1X-SHA256") {
			return "WPA2-Enterprise"
		}
		return "WPA2-PSK"
	}
	if wpa1 {
		return "WPA-TKIP"
	}
	if privacy {
		return "WEP"
	}
	return "OPEN"
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ============================================================================
//  Channel / frequency maps (2.4 / 5 / 6 GHz)
// ============================================================================

func freqToChannel(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115: // 6 GHz
		return (mhz - 5950) / 5
	}
	return 0
}

func channelToFreq(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	case ch >= 32 && ch <= 177:
		return 5000 + ch*5
	}
	return 0
}

func bandForChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 32 && ch <= 177:
		return "5GHz"
	case ch >= 1 && ch <= 233:
		return "6GHz"
	}
	return "?"
}

func bandForFreq(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 4900 && mhz < 5900:
		return "5GHz"
	case mhz >= 5925 && mhz <= 7125:
		return "6GHz"
	}
	return "?"
}

// is24NonOverlap reports whether a 2.4GHz channel is one of 1/6/11.
func is24NonOverlap(ch int) bool { return ch == 1 || ch == 6 || ch == 11 }

// dfsChannel reports whether a 5GHz channel requires DFS.
func dfsChannel(ch int) bool {
	return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144)
}

// signalQuality maps dBm to a 0..100 quality and label.
func signalQuality(dbm int) (int, string) {
	q := 2 * (dbm + 100)
	q = clampInt(q, 0, 100)
	label := "Unusable"
	switch {
	case dbm >= -50:
		label = "Excellent"
	case dbm >= -60:
		label = "Good"
	case dbm >= -70:
		label = "Fair"
	case dbm >= -80:
		label = "Weak"
	}
	return q, label
}

// ============================================================================
//  EAPOL / 802.1X key-frame parser
// ============================================================================

type eapolKey struct {
	Valid       bool
	Version     int
	Type        int
	KeyDescType int
	KeyInfo     uint16
	KeyLength   int
	ReplayCtr   uint64
	Nonce       []byte
	KeyIV       []byte
	KeyRSC      []byte
	MIC         []byte
	KeyDataLen  int
	KeyData     []byte
	MsgNum      int // 1..4 within 4-way handshake
	Pairwise    bool
	Install     bool
	ACK         bool
	MICSet      bool
	Secure      bool
	HasPMKID    bool
	PMKID       []byte
}

// parseEAPOL parses an EAPOL frame body (after the LLC/SNAP, starting at the
// EAPOL version byte). micLen chosen by key descriptor.
func parseEAPOL(b []byte) eapolKey {
	var k eapolKey
	if len(b) < 4 {
		return k
	}
	k.Version = int(b[0])
	k.Type = int(b[1])
	plen := int(binary.BigEndian.Uint16(b[2:4]))
	if k.Type != 3 { // 3 = EAPOL-Key
		return k
	}
	body := b[4:]
	if plen <= len(body) {
		body = body[:plen]
	}
	if len(body) < 95 {
		return k
	}
	k.Valid = true
	k.KeyDescType = int(body[0])
	k.KeyInfo = binary.BigEndian.Uint16(body[1:3])
	k.KeyLength = int(binary.BigEndian.Uint16(body[3:5]))
	k.ReplayCtr = binary.BigEndian.Uint64(body[5:13])
	k.Nonce = append([]byte(nil), body[13:45]...)
	k.KeyIV = append([]byte(nil), body[45:61]...)
	k.KeyRSC = append([]byte(nil), body[61:69]...)
	// 69:77 reserved
	k.MIC = append([]byte(nil), body[77:93]...)
	k.KeyDataLen = int(binary.BigEndian.Uint16(body[93:95]))
	if 95+k.KeyDataLen <= len(body) {
		k.KeyData = append([]byte(nil), body[95:95+k.KeyDataLen]...)
	}
	ki := k.KeyInfo
	k.Pairwise = ki&0x0008 != 0
	k.Install = ki&0x0040 != 0
	k.ACK = ki&0x0080 != 0
	k.MICSet = ki&0x0100 != 0
	k.Secure = ki&0x0200 != 0
	// classify message number of 4-way handshake
	switch {
	case k.ACK && !k.MICSet && !k.Install:
		k.MsgNum = 1
	case !k.ACK && k.MICSet && !k.Secure && !k.Install:
		k.MsgNum = 2
	case k.ACK && k.MICSet && k.Install:
		k.MsgNum = 3
	case !k.ACK && k.MICSet && k.Secure && !k.Install:
		k.MsgNum = 4
	}
	// scan key data for PMKID KDE (00-0F-AC type 4)
	k.PMKID, k.HasPMKID = extractPMKID(k.KeyData)
	return k
}

func extractPMKID(kd []byte) ([]byte, bool) {
	pos := 0
	for pos+2 <= len(kd) {
		if kd[pos] != 0xdd {
			// not a KDE; bail (RSN KDE uses 0xdd type)
			break
		}
		l := int(kd[pos+1])
		if pos+2+l > len(kd) {
			break
		}
		kde := kd[pos+2 : pos+2+l]
		if len(kde) >= 4 && kde[0] == 0x00 && kde[1] == 0x0f && kde[2] == 0xac && kde[3] == 0x04 {
			if len(kde) >= 20 {
				return append([]byte(nil), kde[4:20]...), true
			}
		}
		pos += 2 + l
	}
	return nil, false
}

// findEAPOLInPayload locates an EAPOL payload within a data frame body by
// scanning for the 888E ethertype after LLC/SNAP (AA AA 03 00 00 00 88 8E).
func findEAPOLInPayload(body []byte) []byte {
	snap := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}
	if idx := bytes.Index(body, snap); idx >= 0 {
		return body[idx+8:]
	}
	// try raw 888E
	e := []byte{0x88, 0x8e}
	if idx := bytes.Index(body, e); idx >= 0 && idx+2 < len(body) {
		return body[idx+2:]
	}
	return nil
}

// ============================================================================
//  Findings + Report model and 5-format export engine
// ============================================================================

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Entity      string   `json:"entity"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	MITRE       []string `json:"mitre,omitempty"`
}

type Report struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Target    string            `json:"target"`
	Generated string            `json:"generated"`
	Grade     string            `json:"grade"`
	Score     float64           `json:"score"`
	Summary   map[string]string `json:"summary"`
	Findings  []Finding         `json:"findings"`
	Data      interface{}       `json:"data,omitempty"` // tool-specific structured detail (JSON export)
	TextBody  string            `json:"-"`
}

func newReport(target string) *Report {
	return &Report{
		Tool:      APPNAME,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Summary:   map[string]string{},
	}
}

func (rep *Report) add(f Finding) {
	if f.Severity == "" {
		f.Severity = scoreToSeverity(f.Score)
	}
	rep.Findings = append(rep.Findings, f)
}

func (rep *Report) sortFindings() {
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		ri, rj := sevRank(rep.Findings[i].Severity), sevRank(rep.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return rep.Findings[i].Score > rep.Findings[j].Score
	})
}

func (rep *Report) countBySeverity() map[string]int {
	m := map[string]int{}
	for _, f := range rep.Findings {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}

// computeGrade derives a posture grade from finding severities.
func (rep *Report) computeGrade() {
	penalty := 0.0
	for _, f := range rep.Findings {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			penalty += 22
		case SevHigh:
			penalty += 12
		case SevMedium:
			penalty += 6
		case SevLow:
			penalty += 2
		}
	}
	score := clamp(100-penalty, 0, 100)
	rep.Score = score
	rep.Grade = gradeFromScore(score)
}

func summaryKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---------------------------------------------------------------------------
//  Export: TXT
// ---------------------------------------------------------------------------

func exportTXT(rep *Report) string {
	var sb strings.Builder
	w := 72
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("%s  —  %s\n", APPNAME, TAGLINE))
	sb.WriteString("Author: khaled.s.haddad    Website: owlsec.org\n")
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("Target     : %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("Generated  : %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("Version    : %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("Posture    : %s  (score %.1f/100 — %s)\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	sb.WriteString(hr(w) + "\n\n")
	if len(rep.Summary) > 0 {
		sb.WriteString("SUMMARY\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("  %-24s %s\n", k+":", rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n")
	}
	counts := rep.countBySeverity()
	sb.WriteString(fmt.Sprintf("FINDINGS (%d)  [C:%d H:%d M:%d L:%d I:%d]\n",
		len(rep.Findings), counts[SevCritical], counts[SevHigh],
		counts[SevMedium], counts[SevLow], counts[SevInfo]))
	sb.WriteString(hr(w) + "\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("[%d] (%s) %s\n", i+1, f.Severity, f.Title))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("    Entity : %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("    Detail : %s\n", f.Detail))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("    MITRE  : %s\n", strings.Join(f.MITRE, ", ")))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Fix    : %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(hr(w) + "\n")
	sb.WriteString("Authorized testing only. Generated by " + APPNAME + " v" + VERSION + ".\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Export: Markdown
// ---------------------------------------------------------------------------

func exportMD(rep *Report) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s — Report\n\n", APPNAME))
	sb.WriteString(fmt.Sprintf("*%s*\n\n", TAGLINE))
	sb.WriteString(fmt.Sprintf("- **Target:** %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("- **Generated:** %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("- **Version:** %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("- **Posture:** `%s` (score %.1f/100 — %s)\n\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	if len(rep.Summary) > 0 {
		sb.WriteString("## Summary\n\n")
		sb.WriteString("| Metric | Value |\n|---|---|\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", k, rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString("## Details\n\n```\n")
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n```\n\n")
	}
	sb.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(rep.Findings)))
	sb.WriteString("| # | Severity | Title | Entity | MITRE |\n|---|---|---|---|---|\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), mdEsc(f.Entity), strings.Join(f.MITRE, " ")))
	}
	sb.WriteString("\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("- **Entity:** %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("- **Detail:** %s\n", f.Detail))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK:** %s\n", strings.Join(f.MITRE, ", ")))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n---\n*Authorized testing only. " + APPNAME + " v" + VERSION + " — owlsec.org*\n")
	return sb.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ---------------------------------------------------------------------------
//  Export: JSON
// ---------------------------------------------------------------------------

func exportJSON(rep *Report) string {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
//  Export: CSV
// ---------------------------------------------------------------------------

func exportCSV(rep *Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "title", "entity", "detail", "mitre", "remediation"})
	for i, f := range rep.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1),
			f.Severity,
			fmt.Sprintf("%.1f", f.Score),
			f.Title,
			f.Entity,
			f.Detail,
			strings.Join(f.MITRE, " "),
			f.Remediation,
		})
	}
	w.Flush()
	return buf.String()
}

// ---------------------------------------------------------------------------
//  Export: SARIF 2.1.0
// ---------------------------------------------------------------------------

func exportSARIF(rep *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifProps struct {
		Severity string   `json:"severity,omitempty"`
		Score    float64  `json:"score,omitempty"`
		MITRE    []string `json:"mitre,omitempty"`
		Entity   string   `json:"entity,omitempty"`
	}
	type sarifRule struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		ShortDescription sarifMsg   `json:"shortDescription"`
		FullDescription  sarifMsg   `json:"fullDescription"`
		HelpURI          string     `json:"helpUri,omitempty"`
		Properties       sarifProps `json:"properties"`
	}
	type sarifArtifactLoc struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}
	type sarifPhysLoc struct {
		ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
		Region           sarifRegion      `json:"region"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string     `json:"ruleId"`
		Level      string     `json:"level"`
		Message    sarifMsg   `json:"message"`
		Locations  []sarifLoc `json:"locations"`
		Properties sarifProps `json:"properties"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifToolBlock struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifToolBlock `json:"tool"`
		Results []sarifResult  `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	ruleIdx := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for i, f := range rep.Findings {
		rid := f.ID
		if rid == "" {
			rid = fmt.Sprintf("%s-RULE-%d", APPNAME, i+1)
		}
		if !ruleIdx[rid] {
			ruleIdx[rid] = true
			rules = append(rules, sarifRule{
				ID:               rid,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: f.Detail},
				HelpURI:          "https://owlsec.org",
				Properties:       sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE},
			})
		}
		entity := f.Entity
		if entity == "" {
			entity = rep.Target
		}
		results = append(results, sarifResult{
			RuleID:  rid,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: f.Detail},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhysLoc{
				ArtifactLocation: sarifArtifactLoc{URI: entity},
				Region:           sarifRegion{StartLine: 1},
			}}},
			Properties: sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE, Entity: f.Entity},
		})
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifToolBlock{Driver: sarifDriver{
				Name:           APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// renderReport returns the report in the requested format.
func renderReport(rep *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "txt", "text", "":
		return exportTXT(rep), nil
	case "md", "markdown":
		return exportMD(rep), nil
	case "json":
		return exportJSON(rep), nil
	case "csv":
		return exportCSV(rep), nil
	case "sarif":
		return exportSARIF(rep), nil
	}
	return "", fmt.Errorf("unknown format %q (use txt|md|json|csv|sarif)", format)
}

// writeReport emits to stdout or a file.
func writeReport(rep *Report, format, outPath string) error {
	out, err := renderReport(rep, format)
	if err != nil {
		return err
	}
	if outPath == "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(outPath, []byte(out), 0644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(outPath)
	okMsg("Report written: " + abs + " (" + format + ")")
	return nil
}

// ============================================================================
//  HOW TO USE renderer (mandatory help view) + CLI plumbing
// ============================================================================

type howSection struct {
	Title string
	Lines []string
}

// renderHowto prints the full HOW TO USE screen with the cyan owl UI.
func renderHowto(secs []howSection) {
	clear()
	banner()
	for _, s := range secs {
		sectionHeader(s.Title)
		for _, ln := range s.Lines {
			if strings.HasPrefix(ln, "#") {
				fmt.Println("  " + col(strings.TrimPrefix(ln, "#"), YLW+B))
			} else if strings.HasPrefix(ln, "- ") {
				bullet(strings.TrimPrefix(ln, "- "))
			} else if ln == "" {
				fmt.Println()
			} else {
				fmt.Println("  " + col(ln, W))
			}
		}
	}
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only — written permission required.", OR+B))
}

// legalWarningLines is the standard LEGAL & ETHICAL WARNING block shared by all
// tools (each tool appends protocol-specific notes).
func legalWarningLines() []string {
	return []string{
		"This tool is for AUTHORIZED security testing and education ONLY.",
		"",
		"- Use ONLY on networks, devices and spectrum you own or have",
		"  EXPLICIT WRITTEN PERMISSION to assess.",
		"- Interception, jamming, deauthentication or spoofing of radio",
		"  networks without authorization is ILLEGAL in most jurisdictions",
		"  (e.g. CFAA, Computer Misuse Act, Wireless Telegraphy Act, RF",
		"  regulatory law) and may carry criminal penalties.",
		"- This build operates OFFLINE on capture/log files you supply; it",
		"  does not transmit, inject, or control any radio hardware.",
		"- You are solely responsible for lawful, ethical use. The author",
		"  (khaled.s.haddad) and owlsec.org accept NO liability for misuse.",
	}
}

func navigationLines(items []string) []string {
	out := []string{"Use the number keys shown in the main menu:"}
	out = append(out, "")
	for i, it := range items {
		out = append(out, fmt.Sprintf("- [%02d] %s", i+1, it))
	}
	out = append(out, "- [00] Exit the program")
	out = append(out, "")
	out = append(out, "Press Enter at any [↩] prompt to return to the menu.")
	return out
}

// ---------------------------------------------------------------------------
//  CLI helpers
// ---------------------------------------------------------------------------

func printVersion() {
	fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
	fmt.Println("Author : khaled.s.haddad")
	fmt.Println("Website: owlsec.org")
	fmt.Println("Build  : Go stdlib, static (CGO disabled) — " + SUITE)
}

// severitySummaryLine renders a compact finding tally.
func severitySummaryLine(rep *Report) string {
	c := rep.countBySeverity()
	return fmt.Sprintf("Critical:%d High:%d Medium:%d Low:%d Info:%d",
		c[SevCritical], c[SevHigh], c[SevMedium], c[SevLow], c[SevInfo])
}

// printFindingsTable renders findings to the interactive TUI.
func printFindingsTable(rep *Report) {
	if len(rep.Findings) == 0 {
		info("No findings for this run.")
		return
	}
	rows := [][]string{}
	for i, f := range rep.Findings {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			f.Severity,
			truncStr(f.Title, 34),
			truncStr(f.Entity, 20),
			strings.Join(f.MITRE, " "),
		})
	}
	table([]string{"#", "SEVERITY", "FINDING", "ENTITY", "MITRE"}, rows)
}

// gradeBanner prints the posture grade with color.
func gradeBanner(rep *Report) {
	rep.computeGrade()
	g := rep.Grade
	fmt.Println()
	fmt.Println("  " + col(" POSTURE GRADE ", gradeColor(g)+"\033[7m") + "  " +
		col(g, gradeColor(g)) + col(fmt.Sprintf("   score %.1f/100 — %s", rep.Score, gradeLabel(g)), GY))
}

// writeOrShow writes the report (file or stdout) and reports status in the TUI.
func writeOrShow(rep *Report, format, out string) {
	if err := writeReport(rep, format, out); err != nil {
		errMsg(err.Error())
	}
}

// chooseFormat validates a format string.
func chooseFormat(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "txt", "md", "json", "csv", "sarif":
		return s
	}
	return "txt"
}

// parseIntList parses "1,2,3" or "1-11" style lists.
func parseIntList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			r := strings.SplitN(part, "-", 2)
			a := atoiSafe(r[0])
			b := atoiSafe(r[1])
			if a <= b {
				for i := a; i <= b; i++ {
					out = append(out, i)
				}
			}
		} else {
			out = append(out, atoiSafe(part))
		}
	}
	return out
}

// nowStamp is a filesystem-friendly timestamp.
func nowStamp() string { return time.Now().Format("20060102-150405") }

// defaultOutName builds an export filename when the user omits one.
func defaultOutName(kind, format string) string {
	ext := format
	if format == "md" {
		ext = "md"
	}
	return fmt.Sprintf("%s-%s-%s.%s", strings.ToLower(APPNAME), kind, nowStamp(), ext)
}

// ensure helpers are considered used even by lean tools.
var _ = errors.New
var _ = math.Sqrt
var _ = hex.EncodeToString
var _ = sort.Ints
var _ = filepath.Base
var _ = bufio.NewReader

// ============================================================================
//  Tool contract hooks + unified main/CLI/interactive engine
// ============================================================================

// Each tool wires these in its init(). The engine below is identical across the
// batch; the domain depth lives in each tool's hook implementations.
var (
	hookHowto         func() []howSection
	hookDemo          func() *Report
	hookAnalyze       func(path string) (*Report, error)
	hookActions       func() []menuAction
	hookRegisterFlags func(*flag.FlagSet)
	hookUsageExtra    func()
	hookSelfTest      func() (pass, fail int)
)

type menuAction struct {
	label string
	desc  string
	run   func()
}

// lastReport is the most recent analysis result, shared across menu actions.
var lastReport *Report

// common CLI flags
var (
	flagInput    string
	flagFormat   string
	flagOutput   string
	flagNoColor  bool
	flagValidate bool
	flagSelfTest bool
)

func printUsage() {
	if !noColor {
		banner()
	} else {
		fmt.Printf("%s — %s\n", APPNAME, TAGLINE)
		fmt.Println("Author: khaled.s.haddad | owlsec.org")
	}
	fmt.Println()
	fmt.Println(col("USAGE", CY+B))
	fmt.Printf("  %s [flags]\n", APPNAME)
	fmt.Printf("  %s                 # launch the interactive cyan owl TUI\n", APPNAME)
	fmt.Printf("  %s --input FILE    # analyze a capture and print a report\n", APPNAME)
	fmt.Printf("  %s --demo          # run a self-contained synthetic demo\n", APPNAME)
	fmt.Println()
	fmt.Println(col("CORE FLAGS", CY+B))
	fmt.Println("  -h, --help            Show this help")
	fmt.Println("      --version         Show version information")
	fmt.Println("      --howto           Show the HOW TO USE screen (legal, steps, nav)")
	fmt.Println("      --demo            Run a synthetic, self-contained demonstration")
	fmt.Println("      --input FILE      Input capture/log file (alias: --pcap)")
	fmt.Println("      --format FMT      Output format: txt|md|json|csv|sarif (default txt)")
	fmt.Println("      --output FILE     Write report to FILE instead of stdout")
	fmt.Println("      --validate        Parse-check --input and exit 0 (ok) / 1 (fail)")
	fmt.Println("      --selftest        Run built-in self-tests and exit 0 / 1")
	fmt.Println("      --no-color        Disable ANSI colors")
	if hookUsageExtra != nil {
		fmt.Println()
		fmt.Println(col("TOOL FLAGS", CY+B))
		hookUsageExtra()
	}
	fmt.Println()
	fmt.Println(col("CATEGORY", CY+B) + "  " + CATEGORY)
	fmt.Println(col("MITRE   ", CY+B) + "  " + MITRE)
	fmt.Println()
	fmt.Println(col("EXAMPLES", CY+B))
	fmt.Println("  " + APPNAME + " --input capture.pcapng")
	fmt.Println("  " + APPNAME + " --input capture.pcap --window 2 --wave-gap 10")
	fmt.Println("  " + APPNAME + " --input capture.pcap --format sarif --output deauth.sarif")
	fmt.Println("  " + APPNAME + " --input capture.pcap --format json --output deauth.json")
	fmt.Println("  " + APPNAME + " --input capture.pcap --validate && echo \"capture OK\"")
	fmt.Println("  " + APPNAME + " --reason 3            # then menu [04] to view the frame")
	fmt.Println("  " + APPNAME + " --demo")
	fmt.Println()
	fmt.Println(col("Authorized testing only. No warranty. See --howto for legal terms.", DIM))
}

func main() {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var showHelp, showHelpS, showVer, showHowto, demo bool
	fs.BoolVar(&showHelp, "help", false, "show help")
	fs.BoolVar(&showHelpS, "h", false, "show help")
	fs.BoolVar(&showVer, "version", false, "show version")
	fs.BoolVar(&showHowto, "howto", false, "show HOW TO USE")
	fs.BoolVar(&demo, "demo", false, "run synthetic demo")
	fs.StringVar(&flagInput, "input", "", "input capture/log file")
	fs.StringVar(&flagInput, "pcap", "", "input capture file (alias of --input)")
	fs.StringVar(&flagFormat, "format", "txt", "txt|md|json|csv|sarif")
	fs.StringVar(&flagOutput, "output", "", "write report to file")
	fs.BoolVar(&flagValidate, "validate", false, "parse-check --input and exit 0/1")
	fs.BoolVar(&flagSelfTest, "selftest", false, "run built-in self-tests and exit 0/1")
	fs.BoolVar(&flagNoColor, "no-color", false, "disable colors")
	if hookRegisterFlags != nil {
		hookRegisterFlags(fs)
	}
	fs.Usage = printUsage
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			printUsage()
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if flagNoColor {
		noColor = true
	}
	flagFormat = chooseFormat(flagFormat)

	switch {
	case showHelp || showHelpS:
		printUsage()
		return
	case showVer:
		printVersion()
		return
	case showHowto:
		renderHowto(hookHowto())
		return
	case flagSelfTest:
		if hookSelfTest == nil {
			warnMsg("No self-tests registered for this tool.")
			return
		}
		sectionHeader(APPNAME + " — Self-test")
		pass, fail := hookSelfTest()
		fmt.Println()
		if fail == 0 {
			okMsg(fmt.Sprintf("All self-tests passed (%d/%d).", pass, pass))
			os.Exit(0)
		}
		errMsg(fmt.Sprintf("Self-tests failed: %d passed, %d failed.", pass, fail))
		os.Exit(1)
	case flagValidate:
		if flagInput == "" {
			errMsg("--validate requires --input FILE")
			os.Exit(2)
		}
		rep, err := hookAnalyze(flagInput)
		if err != nil {
			errMsg("Parse failed: " + err.Error())
			os.Exit(1)
		}
		okMsg("Capture parsed successfully: " + flagInput)
		for _, k := range summaryKeys(rep.Summary) {
			kvRow(k, rep.Summary[k])
		}
		os.Exit(0)
	case demo:
		rep := hookDemo()
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		if flagOutput == "" && flagFormat == "txt" {
			fmt.Println(col(APPNAME+" — synthetic demo run", CY+B))
		}
		writeOrShow(rep, flagFormat, flagOutput)
		return
	case flagInput != "":
		rep, err := hookAnalyze(flagInput)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		writeOrShow(rep, flagFormat, flagOutput)
		return
	}

	// No actionable flags → interactive TUI.
	if len(os.Args) == 1 {
		standardInteractive()
		return
	}
	// Flags given but nothing to do.
	printUsage()
}

// standardInteractive drives the menu-based cyan owl TUI loop.
func standardInteractive() {
	for {
		acts := hookActions()
		items := make([]menuItem, 0, len(acts)+1)
		for i, a := range acts {
			items = append(items, menuItem{key: fmt.Sprintf("%02d", i+1), name: a.label, desc: a.desc, clr: CY + B})
		}
		sel := strings.TrimSpace(menu(TAGLINE, items))
		if sel == "00" || sel == "0" || strings.EqualFold(sel, "q") || strings.EqualFold(sel, "exit") {
			clear()
			banner()
			okMsg("Session closed. Authorized testing only — stay ethical.")
			return
		}
		if strings.EqualFold(sel, "h") || strings.EqualFold(sel, "help") || sel == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(sel)
		if err != nil {
			continue
		}
		if n >= 1 && n <= len(acts) {
			clear()
			banner()
			acts[n-1].run()
			pause()
			continue
		}
	}
}

// ---------------------------------------------------------------------------
//  Interactive helpers shared by tools
// ---------------------------------------------------------------------------

// promptExistingPath asks for a file path and validates it exists.
func promptExistingPath(label string) (string, bool) {
	p := prompt(label)
	p = strings.TrimSpace(p)
	if p == "" {
		warnMsg("No path entered.")
		return "", false
	}
	if !fileExists(p) {
		errMsg("File not found: " + p)
		return "", false
	}
	return p, true
}

// interactiveExport writes lastReport in a chosen format.
func interactiveExport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Export Report")
	f := chooseFormat(prompt("format txt|md|json|csv|sarif"))
	out := prompt("output file (blank = screen)")
	writeOrShow(lastReport, f, strings.TrimSpace(out))
}

// showLastReport renders the last report to the TUI.
func showLastReport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Last Report — " + lastReport.Target)
	for _, k := range summaryKeys(lastReport.Summary) {
		kvRow(k, lastReport.Summary[k])
	}
	fmt.Println()
	printFindingsTable(lastReport)
	gradeBanner(lastReport)
}

// runDemoInteractive runs the synthetic demo inside the TUI.
func runDemoInteractive() {
	sectionHeader("Synthetic Demo")
	info("Generating self-contained sample data...")
	rep := hookDemo()
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Demo analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// analyzeInteractive prompts for a file and runs the tool's analyzer.
func analyzeInteractive() {
	sectionHeader("Analyze Input File")
	p, ok := promptExistingPath("path to capture/log file")
	if !ok {
		return
	}
	info("Analyzing " + p + " ...")
	rep, err := hookAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		return
	}
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// ============================================================================
//  Generic 802.11 frame-crafting toolkit (offline lab + demo synthesis)
// ============================================================================

// craftWrapPcap wraps raw link-layer frames into a little-endian pcap buffer.
func craftWrapPcap(frames [][]byte, linktype int, usecStep uint32) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linktype))
	b = append(b, hdr...)
	ts := uint32(time.Now().Unix())
	us := uint32(0)
	for _, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], ts)
		binary.LittleEndian.PutUint32(rec[4:8], us)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		b = append(b, rec...)
		b = append(b, fr...)
		us += usecStep
		if us >= 1000000 {
			ts += us / 1000000
			us %= 1000000
		}
	}
	return b
}

// craftBeaconOpen builds a minimal open-network beacon carrying SSID + DS param.
func craftBeaconOpen(bssid []byte, ssid string, ch int) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x11, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftDataEAPOL wraps an EAPOL payload inside an 802.11 data frame (LLC/SNAP).
func craftDataEAPOL(fromDS bool, ap, sta, eapol []byte) []byte {
	var f []byte
	if fromDS {
		f = append(f, 0x08, 0x02, 0x00, 0x00)
		f = append(f, sta...)
		f = append(f, ap...)
		f = append(f, sta...)
	} else {
		f = append(f, 0x08, 0x01, 0x00, 0x00)
		f = append(f, ap...)
		f = append(f, sta...)
		f = append(f, ap...)
	}
	f = append(f, 0x00, 0x00)
	f = append(f, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e)
	f = append(f, eapol...)
	return f
}

// craftProbeReq builds a probe request from a client with a directed SSID.
func craftProbeReq(client []byte, ssid string) []byte {
	var f []byte
	f = append(f, 0x40, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, client...)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, 0x00, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidExtRates, 0x04, 0x0c, 0x12, 0x18, 0x24)
	return f
}

// craftProbeResp builds a probe response from a BSSID to a client for an SSID.
func craftProbeResp(bssid, client []byte, ssid string, ch int, privacy bool) []byte {
	var f []byte
	f = append(f, 0x50, 0x00, 0x00, 0x00)
	f = append(f, client...)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0021)
	if privacy {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftBeaconSec builds a beacon with a chosen security posture (reuses RSN).
func craftBeaconSec(bssid []byte, ssid string, ch int, sec string) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0001)
	if sec != "OPEN" {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c)
	f = append(f, eidDSParam, 0x01, byte(ch))
	switch sec {
	case "WPA2-PSK":
		f = append(f, craftRSN(2, false)...)
	case "WPA3-SAE":
		f = append(f, craftRSN(8, true)...)
	case "WPA2-Enterprise":
		f = append(f, craftRSN(1, false)...)
	}
	return f
}

func craftRSN(akm int, mfpReq bool) []byte {
	var d []byte
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, byte(akm))
	caps := uint16(0x0000)
	if mfpReq {
		caps |= 0x00c0
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	d = append(d, cb...)
	ie := []byte{eidRSN, byte(len(d))}
	return append(ie, d...)
}

// parseBeaconLike extracts SSID/channel/security from a beacon/probe-resp frame.
func parseBeaconLike(f *dot11Frame) (ssid string, ch int, sec string, hidden bool) {
	if len(f.Body) < 12 {
		return "", 0, "OPEN", false
	}
	caps := binary.LittleEndian.Uint16(f.Body[10:12])
	privacy := caps&0x0010 != 0
	ies := parseIEs(f.Body[12:])
	ssid = ieSSID(ies)
	if ssid == "<hidden>" || ssid == "" {
		hidden = true
	}
	ch = ieChannel(ies)
	var rsn rsnInfo
	if r := findIE(ies, eidRSN); r != nil {
		rsn = parseRSN(r)
	}
	sec = securityString(privacy, rsn, parseWPA1(ies))
	return ssid, ch, sec, hidden
}

// ============================================================================
//  ODeauth — 802.11 deauth/disassoc frame lab + flood detector (offline)
// ============================================================================

// IEEE 802.11 reason codes (Table 9-49).
var dxReasonCodes = map[int]string{
	0:  "Reserved",
	1:  "Unspecified reason",
	2:  "Previous auth no longer valid",
	3:  "Deauth: STA leaving / left IBSS or ESS",
	4:  "Disassoc due to inactivity",
	5:  "Disassoc: AP out of resources",
	6:  "Class 2 frame from non-authenticated STA",
	7:  "Class 3 frame from non-associated STA",
	8:  "Disassoc: STA leaving BSS",
	9:  "STA requesting (re)assoc not authenticated",
	10: "Disassoc: power capability unacceptable",
	11: "Disassoc: supported channels unacceptable",
	12: "Disassoc: BSS transition management",
	13: "Invalid element / information element",
	14: "Message integrity code (MIC) failure",
	15: "4-Way Handshake timeout",
	16: "Group Key Handshake timeout",
	17: "Handshake element mismatch",
	18: "Invalid group cipher",
	19: "Invalid pairwise cipher",
	20: "Invalid AKMP",
	21: "Unsupported RSN element version",
	22: "Invalid RSN element capabilities",
	23: "802.1X authentication failed",
	24: "Cipher suite rejected by policy",
	25: "TDLS unreachable",
	26: "TDLS unspecified",
	32: "Disassoc: QoS unspecified",
	33: "Disassoc: QoS AP lacks bandwidth",
	34: "Disassoc: excessive frame loss / poor channel",
	35: "Disassoc: STA transmitting outside TXOP limit",
	36: "Requested from peer (leaving)",
	37: "Requested: do not want mechanism",
	38: "Requested: setup required / timeout",
	39: "Requested: timeout",
	45: "Peer cipher suite unsupported",
}

func dxReason(code int) string {
	if s, ok := dxReasonCodes[code]; ok {
		return s
	}
	return fmt.Sprintf("Vendor/reserved reason %d", code)
}

type dxEvent struct {
	Idx        int
	TsSec      uint32
	TsUsec     uint32
	IsDisassoc bool
	Src        string
	Dst        string
	BSSID      string
	Reason     int
	Broadcast  bool
	Seq        int  // 802.11 sequence number (0..4095)
	Retry      bool // retry bit — retransmissions legitimately repeat Seq
	Protected  bool // 802.11w-protected frame (body encrypted, reason unreadable)
	Signal     int  // radiotap antenna signal in dBm (valid when HasSignal)
	HasSignal  bool
	FreqMHz    int // radiotap channel frequency (0 when absent)
}

// dxBSSInfo is the security posture a BSS advertised in its beacons / probe
// responses, used to judge whether 802.11w (PMF) protects it from deauth.
type dxBSSInfo struct {
	BSSID    string `json:"bssid"`
	SSID     string `json:"ssid"`
	Security string `json:"security"`
	Channel  int    `json:"channel"`
	MFPCap   bool   `json:"pmf_capable"`
	MFPReq   bool   `json:"pmf_required"`
}

// dxPosture is the PMF verdict for one BSS that was targeted by deauth/disassoc.
type dxPosture struct {
	BSSID       string `json:"bssid"`
	SSID        string `json:"ssid,omitempty"`
	Security    string `json:"security,omitempty"`
	PMF         string `json:"pmf"` // required | optional | off | unknown
	Basis       string `json:"basis"`
	Frames      int    `json:"frames"`
	Unprotected int    `json:"unprotected"`
	Protected   int    `json:"protected"`
}

// dxRSSIStat summarises the received signal of one source MAC. A single
// stationary radio lands in one tight signal band; frames from one MAC that
// split into two well-separated, time-interleaved bands come from two
// transmitters — the genuine station and an impersonator.
type dxRSSIStat struct {
	Src         string  `json:"src"`
	Samples     int     `json:"samples"`
	Min         int     `json:"min_dbm"`
	Max         int     `json:"max_dbm"`
	Mean        float64 `json:"mean_dbm"`
	Split       bool    `json:"split"`
	LowMean     float64 `json:"low_mean_dbm,omitempty"`
	HighMean    float64 `json:"high_mean_dbm,omitempty"`
	LowN        int     `json:"low_n,omitempty"`
	HighN       int     `json:"high_n,omitempty"`
	Gap         int     `json:"gap_db,omitempty"`
	Transitions int     `json:"transitions,omitempty"`
}

// dxWave is one burst of deauth/disassoc activity, separated from the next by
// at least the --wave-gap of silence.
type dxWave struct {
	N         int     `json:"wave"`
	StartSec  float64 `json:"start_offset_s"`
	EndSec    float64 `json:"end_offset_s"`
	Duration  float64 `json:"duration_s"`
	Frames    int     `json:"frames"`
	Rate      float64 `json:"rate_fps"`
	Broadcast int     `json:"broadcast"`
	TopSrc    string  `json:"top_src"`
	TopReason int     `json:"top_reason"`
	Channels  []int   `json:"channels,omitempty"`
}

// dxChanHop records a source MAC seen on more than one non-overlapping channel.
type dxChanHop struct {
	Src      string `json:"src"`
	Channels []int  `json:"channels"`
	Frames   int    `json:"frames"`
	Beacon   int    `json:"beacon_channel,omitempty"` // channel its BSS advertises, if known
}

type dxResult struct {
	Target      string
	Events      []dxEvent
	TotalFrames int
	DeauthN     int
	DisassocN   int
	BySrc       map[string]int
	ByVictim    map[string]int
	ByReason    map[int]int
	Broadcast   int
	WindowSec   int
	PeakRate    float64
	MinGapMs    float64 // smallest inter-frame gap among deauth/disassoc events
	MicroBursts int     // adjacent frame pairs spaced < 2 ms apart (injection tell)
	TopVictim   string  // addressed MAC receiving the most frames
	TopVictimN  int
	SpoofSrc    []dxSeqStat          // per-source sequence-number spoofing analysis
	ByBSSID     map[string]int       // deauth/disassoc frames per BSSID (Addr3)
	Links       []dxLink             // (BSS → victim) targeting pairs, desc by count
	MultiBSSID  []dxMultiBSS         // sources transmitting under more than one BSSID
	ProtectedN  int                  // 802.11w-protected deauth/disassoc frames
	BSSInfo     map[string]dxBSSInfo // advertised posture per BSSID (beacons/probe-resp)
	Posture     []dxPosture          // PMF verdict per targeted BSS, desc by frames
	RSSI        []dxRSSIStat         // per-source signal stats (radiotap captures)
	Waves       []dxWave             // attack waves in chronological order
	WaveGap     int                  // silence (s) that separates two waves
	ByFreq      map[int]int          // deauth/disassoc frames per capture frequency (MHz)
	ByBand      map[string]int       // deauth/disassoc frames per band
	ChanHops    []dxChanHop          // sources spanning non-overlapping channels
}

var dxState *dxResult
var dxFlagReason int
var dxFlagWindow int
var dxFlagWaveGap int

func dxAnalyzeCap(cf *capFile, target string) *dxResult {
	win := dxFlagWindow
	if win < 1 {
		win = 1
	}
	gap := dxFlagWaveGap
	if gap < 1 {
		gap = 5
	}
	res := &dxResult{Target: target, BySrc: map[string]int{}, ByVictim: map[string]int{}, ByReason: map[int]int{}, ByBSSID: map[string]int{}, WindowSec: win,
		BSSInfo: map[string]dxBSSInfo{}, WaveGap: gap, ByFreq: map[int]int{}, ByBand: map[string]int{}}
	for _, pkt := range cf.Packets {
		res.TotalFrames++
		data := pkt.Data
		var rt radiotapInfo
		if pkt.LinkType == DLT_RADIOTAP {
			rt, data = parseRadiotap(data)
		} else if pkt.LinkType == DLT_PPI && len(data) >= 8 {
			l := int(binary.LittleEndian.Uint16(data[2:4]))
			if l > 0 && l <= len(data) {
				data = data[l:]
			}
		}
		f, err := parseDot11(data)
		if err != nil || f.Type != TypeMgmt {
			continue
		}
		if f.Subtype == MgmtBeacon || f.Subtype == MgmtProbeResp {
			if bi, ok := dxParseBSSInfo(f); ok {
				if old, seen := res.BSSInfo[bi.BSSID]; !seen || (old.SSID == "" && bi.SSID != "") {
					res.BSSInfo[bi.BSSID] = bi
				}
			}
			continue
		}
		if f.Subtype != MgmtDeauth && f.Subtype != MgmtDisassoc {
			continue
		}
		ev := dxEvent{Idx: pkt.Index, TsSec: pkt.TsSec, TsUsec: pkt.TsUsec, IsDisassoc: f.Subtype == MgmtDisassoc}
		ev.Dst = macStr(f.Addr1)
		ev.Src = macStr(f.Addr2)
		ev.BSSID = macStr(f.Addr3)
		ev.Broadcast = macIsBroadcast(f.Addr1)
		ev.Seq = f.SeqNum
		ev.Retry = f.Retry
		ev.Protected = f.Protected
		if rt.HasSignal && !rt.BadFCS {
			ev.Signal, ev.HasSignal = int(rt.SignalDBm), true
		}
		if rt.HasChannel {
			ev.FreqMHz = int(rt.ChannelMHz)
		}
		// A PMF-protected frame's body is CCMP-encrypted, so the reason code is
		// unreadable; leave it at 0 and keep it out of the reason histogram.
		if len(f.Body) >= 2 && !ev.Protected {
			ev.Reason = int(binary.LittleEndian.Uint16(f.Body[0:2]))
		}
		res.Events = append(res.Events, ev)
		if ev.IsDisassoc {
			res.DisassocN++
		} else {
			res.DeauthN++
		}
		res.BySrc[ev.Src]++
		if ev.Broadcast {
			res.Broadcast++
		} else {
			res.ByVictim[ev.Dst]++
		}
		if ev.Protected {
			res.ProtectedN++
		} else {
			res.ByReason[ev.Reason]++
		}
		if ev.FreqMHz > 0 {
			res.ByFreq[ev.FreqMHz]++
			res.ByBand[bandForFreq(ev.FreqMHz)]++
		}
	}
	// dxPeakRate sorts res.Events by time in place, so burst metrics below
	// observe a chronologically ordered slice.
	res.PeakRate = dxPeakRate(res.Events, win)
	res.MinGapMs, res.MicroBursts = dxBurstMetrics(res.Events)
	// Events are now chronologically ordered — safe for the per-source
	// sequence-number walk that classifies spoofed source MACs.
	res.SpoofSrc = dxSeqAnalysis(res.Events)
	// Correlate victims to the BSS they were attacked on and the source doing it.
	dxCorrelate(res)
	res.Posture = dxPMFPosture(res)
	res.RSSI = dxRSSIAnalysis(res.Events)
	res.Waves = dxWaves(res.Events, gap)
	res.ChanHops = dxChannelHops(res)
	for v, n := range res.ByVictim {
		if n > res.TopVictimN {
			res.TopVictimN = n
			res.TopVictim = v
		}
	}
	dxState = res
	return res
}

// dxBurstMetrics walks the (time-sorted) events and returns the smallest
// inter-frame gap in milliseconds and the number of adjacent pairs spaced
// under 2 ms apart — a cadence hand-driven stations do not produce, and a
// strong tell for tool-driven management-frame injection.
func dxBurstMetrics(events []dxEvent) (float64, int) {
	if len(events) < 2 {
		return 0, 0
	}
	tf := func(e dxEvent) float64 { return float64(e.TsSec) + float64(e.TsUsec)/1e6 }
	minGap := math.MaxFloat64
	bursts := 0
	for i := 1; i < len(events); i++ {
		g := (tf(events[i]) - tf(events[i-1])) * 1000.0
		if g < 0 {
			g = 0
		}
		if g < minGap {
			minGap = g
		}
		if g < 2.0 {
			bursts++
		}
	}
	if minGap == math.MaxFloat64 {
		minGap = 0
	}
	return minGap, bursts
}

// dxPeakRate finds the maximum deauth frames per windowSec sliding window.
func dxPeakRate(events []dxEvent, windowSec int) float64 {
	if len(events) == 0 {
		return 0
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].TsSec != events[j].TsSec {
			return events[i].TsSec < events[j].TsSec
		}
		return events[i].TsUsec < events[j].TsUsec
	})
	best := 0.0
	j := 0
	tf := func(e dxEvent) float64 { return float64(e.TsSec) + float64(e.TsUsec)/1e6 }
	for i := range events {
		for tf(events[i])-tf(events[j]) > float64(windowSec) {
			j++
		}
		cnt := float64(i - j + 1)
		if cnt > best {
			best = cnt
		}
	}
	return best / float64(windowSec)
}

// dxSeqStat summarises the 802.11 sequence-number behaviour of one source MAC.
// A genuine transmitter advances its 12-bit sequence counter by one for each
// new (non-retransmitted) frame, wrapping at 4096. Injected or spoofed frames
// almost never reproduce the impersonated station's live counter, so the
// counter either freezes or steps around incoherently.
type dxSeqStat struct {
	Src      string
	Frames   int     // non-retry frames considered
	Distinct int     // distinct sequence numbers among them
	TopSeq   int     // most frequent sequence number
	TopShare float64 // fraction of frames carrying TopSeq
	Regress  int     // adjacent (time-ordered) pairs whose counter moved backward
	RegShare float64 // Regress / (Frames-1)
	Verdict  string  // "static" (frozen) or "anomalous" (incoherent)
}

// dxSeqDelta returns the signed mod-4096 distance from a to b, in [-2048,2047].
// It lets a monotonic counter that wraps 4095→0 read as a forward step rather
// than a huge backward jump.
func dxSeqDelta(a, b int) int {
	return ((b - a + 2048) & 0xfff) - 2048
}

// dxSeqAnalysis groups time-ordered events by source MAC and classifies each
// source's sequence-number stream, returning only the sources that look
// spoofed. Events are assumed already sorted by time (dxPeakRate orders
// res.Events in place before this runs). Retransmissions are excluded because
// they legitimately repeat the counter.
func dxSeqAnalysis(events []dxEvent) []dxSeqStat {
	type acc struct {
		n        int
		counts   map[int]int
		regress  int
		prev     int
		havePrev bool
	}
	order := []string{}
	m := map[string]*acc{}
	for _, e := range events {
		if e.Retry {
			continue
		}
		a := m[e.Src]
		if a == nil {
			a = &acc{counts: map[int]int{}}
			m[e.Src] = a
			order = append(order, e.Src)
		}
		a.n++
		a.counts[e.Seq]++
		if a.havePrev && dxSeqDelta(a.prev, e.Seq) < 0 {
			a.regress++
		}
		a.prev = e.Seq
		a.havePrev = true
	}
	var out []dxSeqStat
	for _, src := range order {
		a := m[src]
		if a.n < 6 { // too few frames to judge a counter
			continue
		}
		top, topc := 0, -1
		for s, c := range a.counts {
			if c > topc || (c == topc && s < top) {
				top, topc = s, c
			}
		}
		st := dxSeqStat{
			Src: src, Frames: a.n, Distinct: len(a.counts),
			TopSeq: top, TopShare: float64(topc) / float64(a.n),
			Regress: a.regress,
		}
		if a.n > 1 {
			st.RegShare = float64(a.regress) / float64(a.n-1)
		}
		switch {
		case st.Distinct == 1 || (st.TopShare >= 0.8 && a.n >= 10):
			st.Verdict = "static"
		case st.RegShare >= 0.35 || (st.Distinct*4 <= a.n && a.n >= 12):
			st.Verdict = "anomalous"
		}
		if st.Verdict != "" {
			out = append(out, st)
		}
	}
	return out
}

// dxLink ties one targeted client to the BSS it was attacked on and the
// source MAC that predominantly addressed it.
type dxLink struct {
	BSSID  string
	Victim string
	Count  int
	TopSrc string // dominant source MAC addressing this victim on this BSS
}

// dxMultiBSS records a source MAC observed transmitting deauth/disassoc under
// more than one BSSID. A genuine access point owns exactly one BSSID, so a
// source spanning several is a strong rogue-injector / AP-spoofing signal.
type dxMultiBSS struct {
	Src    string
	BSSIDs []string // distinct BSSIDs (≥3 frames each) this source used
	Frames int      // total frames from this source
}

// dxCorrelate links victims ↔ BSSID ↔ source. It fills res.ByBSSID, the sorted
// targeting links (res.Links), and the multi-BSSID source list (res.MultiBSSID).
func dxCorrelate(res *dxResult) {
	type pairAgg struct {
		count int
		src   map[string]int
	}
	pairs := map[string]*pairAgg{}
	srcB := map[string]map[string]int{} // source → BSSID → frame count
	for _, e := range res.Events {
		res.ByBSSID[e.BSSID]++
		if srcB[e.Src] == nil {
			srcB[e.Src] = map[string]int{}
		}
		srcB[e.Src][e.BSSID]++
		if e.Broadcast {
			continue // broadcast has no single addressed victim
		}
		k := e.BSSID + "\x00" + e.Dst
		p := pairs[k]
		if p == nil {
			p = &pairAgg{src: map[string]int{}}
			pairs[k] = p
		}
		p.count++
		p.src[e.Src]++
	}
	for k, p := range pairs {
		i := strings.IndexByte(k, 0)
		top, topc := "", -1
		for s, c := range p.src {
			if c > topc || (c == topc && s < top) {
				top, topc = s, c
			}
		}
		res.Links = append(res.Links, dxLink{BSSID: k[:i], Victim: k[i+1:], Count: p.count, TopSrc: top})
	}
	sort.Slice(res.Links, func(i, j int) bool {
		if res.Links[i].Count != res.Links[j].Count {
			return res.Links[i].Count > res.Links[j].Count
		}
		return res.Links[i].Victim < res.Links[j].Victim
	})
	// A source qualifies as multi-BSSID only when it put ≥3 frames on each of
	// ≥2 BSSIDs — enough to rule out a client legitimately deauthing as it roams.
	for src, set := range srcB {
		qual, total := []string{}, 0
		for b, c := range set {
			total += c
			if c >= 3 {
				qual = append(qual, b)
			}
		}
		if len(qual) >= 2 {
			sort.Strings(qual)
			res.MultiBSSID = append(res.MultiBSSID, dxMultiBSS{Src: src, BSSIDs: qual, Frames: total})
		}
	}
	sort.Slice(res.MultiBSSID, func(i, j int) bool {
		if len(res.MultiBSSID[i].BSSIDs) != len(res.MultiBSSID[j].BSSIDs) {
			return len(res.MultiBSSID[i].BSSIDs) > len(res.MultiBSSID[j].BSSIDs)
		}
		return res.MultiBSSID[i].Src < res.MultiBSSID[j].Src
	})
}

// dxParseBSSInfo reads the advertised security posture from a beacon or probe
// response, including the RSN capabilities' MFPC/MFPR (802.11w) bits.
func dxParseBSSInfo(f *dot11Frame) (dxBSSInfo, bool) {
	if len(f.Addr3) < 6 || len(f.Body) < 12 {
		return dxBSSInfo{}, false
	}
	caps := binary.LittleEndian.Uint16(f.Body[10:12])
	ies := parseIEs(f.Body[12:])
	var rsn rsnInfo
	if r := findIE(ies, eidRSN); r != nil {
		rsn = parseRSN(r)
	}
	bi := dxBSSInfo{
		BSSID: macStr(f.Addr3), SSID: ieSSID(ies), Channel: ieChannel(ies),
		Security: securityString(caps&0x0010 != 0, rsn, parseWPA1(ies)),
		MFPCap:   rsn.MFPCapable || rsn.MFPRequired, MFPReq: rsn.MFPRequired,
	}
	return bi, true
}

// dxPMFPosture judges, for every BSS that deauth/disassoc frames were sent
// under, whether 802.11w protects its clients. The verdict comes from the
// BSS's own beacon (RSN MFPC/MFPR) when one was captured, else from the 6 GHz
// band (where PMF is mandatory), else from protected frames seen in the wild.
func dxPMFPosture(res *dxResult) []dxPosture {
	type agg struct{ n, unprot, prot, sixG int }
	m := map[string]*agg{}
	for _, e := range res.Events {
		if e.BSSID == "ff:ff:ff:ff:ff:ff" || e.BSSID == "" {
			continue
		}
		a := m[e.BSSID]
		if a == nil {
			a = &agg{}
			m[e.BSSID] = a
		}
		a.n++
		if e.Protected {
			a.prot++
		} else {
			a.unprot++
		}
		if e.FreqMHz > 0 && bandForFreq(e.FreqMHz) == "6GHz" {
			a.sixG++
		}
	}
	var out []dxPosture
	for b, a := range m {
		p := dxPosture{BSSID: b, Frames: a.n, Unprotected: a.unprot, Protected: a.prot}
		if bi, ok := res.BSSInfo[b]; ok {
			p.SSID, p.Security = bi.SSID, bi.Security
			switch {
			case bi.MFPReq:
				p.PMF, p.Basis = "required", "beacon RSN MFPR=1"
			case bi.MFPCap:
				p.PMF, p.Basis = "optional", "beacon RSN MFPC=1, MFPR=0"
			case bi.Security == "OPEN" || bi.Security == "WEP" || bi.Security == "WPA-TKIP":
				p.PMF, p.Basis = "off", "beacon: "+bi.Security+" cannot negotiate PMF"
			default:
				p.PMF, p.Basis = "off", "beacon RSN MFPC=0"
			}
		} else if a.sixG > 0 {
			p.PMF, p.Basis = "required", "6 GHz band mandates PMF"
		} else if a.prot > 0 {
			p.PMF, p.Basis = "in-use", "protected deauth frames observed (no beacon)"
		} else {
			p.PMF, p.Basis = "unknown", "no beacon captured for this BSS"
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Frames != out[j].Frames {
			return out[i].Frames > out[j].Frames
		}
		return out[i].BSSID < out[j].BSSID
	})
	return out
}

// dxRSSIAnalysis computes per-source signal statistics and flags sources whose
// frames split into two separated signal bands that alternate over time. The
// alternation requirement (≥4 band switches) keeps a client simply walking
// away from the sensor — one gradual shift — from reading as a split.
func dxRSSIAnalysis(events []dxEvent) []dxRSSIStat {
	order := []string{}
	m := map[string][]int{}
	for _, e := range events {
		if !e.HasSignal {
			continue
		}
		if _, ok := m[e.Src]; !ok {
			order = append(order, e.Src)
		}
		m[e.Src] = append(m[e.Src], e.Signal)
	}
	var out []dxRSSIStat
	for _, src := range order {
		vals := m[src]
		st := dxRSSIStat{Src: src, Samples: len(vals), Min: vals[0], Max: vals[0]}
		sum := 0
		for _, v := range vals {
			sum += v
			if v < st.Min {
				st.Min = v
			}
			if v > st.Max {
				st.Max = v
			}
		}
		st.Mean = float64(sum) / float64(len(vals))
		if len(vals) >= 10 {
			sorted := append([]int(nil), vals...)
			sort.Ints(sorted)
			cut, gap := 0, 0
			for i := 1; i < len(sorted); i++ {
				if g := sorted[i] - sorted[i-1]; g > gap {
					gap, cut = g, sorted[i-1]
				}
			}
			var lo, hi []float64
			for _, v := range vals {
				if v <= cut {
					lo = append(lo, float64(v))
				} else {
					hi = append(hi, float64(v))
				}
			}
			minN := len(vals) / 10
			if minN < 3 {
				minN = 3
			}
			if gap >= 8 && len(lo) >= minN && len(hi) >= minN {
				lm, hm := meanF(lo), meanF(hi)
				trans, prevHi := 0, vals[0] > cut
				for _, v := range vals[1:] {
					if isHi := v > cut; isHi != prevHi {
						trans++
						prevHi = isHi
					}
				}
				if hm-lm >= 12 && stddevF(lo) <= 6 && stddevF(hi) <= 6 && trans >= 4 {
					st.Split = true
					st.LowMean, st.HighMean = lm, hm
					st.LowN, st.HighN = len(lo), len(hi)
					st.Gap, st.Transitions = gap, trans
				}
			}
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Samples > out[j].Samples })
	return out
}

// dxEvTime returns an event's capture timestamp in fractional seconds.
func dxEvTime(e dxEvent) float64 { return float64(e.TsSec) + float64(e.TsUsec)/1e6 }

// dxWaves splits the time-sorted events into attack waves: runs of frames with
// no silence longer than gapSec between neighbours.
func dxWaves(events []dxEvent, gapSec int) []dxWave {
	if len(events) == 0 {
		return nil
	}
	t0 := dxEvTime(events[0])
	var out []dxWave
	flush := func(ev []dxEvent) {
		w := dxWave{N: len(out) + 1, Frames: len(ev)}
		w.StartSec, w.EndSec = dxEvTime(ev[0])-t0, dxEvTime(ev[len(ev)-1])-t0
		ms := func(x float64) float64 { return math.Round(x*1000) / 1000 }
		w.StartSec, w.EndSec = ms(w.StartSec), ms(w.EndSec)
		w.Duration = ms(w.EndSec - w.StartSec)
		src, rsn, chs := map[string]int{}, map[int]int{}, map[int]bool{}
		for _, e := range ev {
			src[e.Src]++
			if !e.Protected {
				rsn[e.Reason]++
			}
			if e.Broadcast {
				w.Broadcast++
			}
			if e.FreqMHz > 0 {
				chs[freqToChannel(e.FreqMHz)] = true
			}
		}
		if top := dxTopN(src, 1); len(top) > 0 {
			w.TopSrc = top[0].k
		}
		best := -1
		for r, c := range rsn {
			if c > best || (c == best && r < w.TopReason) {
				w.TopReason, best = r, c
			}
		}
		for c := range chs {
			w.Channels = append(w.Channels, c)
		}
		sort.Ints(w.Channels)
		// A single-frame wave has no duration; report its rate as frames/1s.
		w.Rate = float64(w.Frames) / math.Max(w.Duration, 1)
		out = append(out, w)
	}
	start := 0
	for i := 1; i < len(events); i++ {
		if dxEvTime(events[i])-dxEvTime(events[i-1]) > float64(gapSec) {
			flush(events[start:i])
			start = i
		}
	}
	flush(events[start:])
	return out
}

// dxChanDistinct reports whether two capture frequencies are separate channels
// rather than one transmitter leaking into its neighbour. Overlapping 2.4 GHz
// channels (less than 5 apart) bleed into each other, so a sensor on ch5 hears
// an AP on ch6; only non-overlapping spacing counts as a distinct channel.
func dxChanDistinct(fa, fb int) bool {
	if bandForFreq(fa) == "2.4GHz" && bandForFreq(fb) == "2.4GHz" {
		d := freqToChannel(fa) - freqToChannel(fb)
		if d < 0 {
			d = -d
		}
		return d >= 5
	}
	return fa != fb
}

// dxChannelHops finds sources that transmitted deauth/disassoc on two or more
// non-overlapping channels (≥3 frames each). An access point's radio sits on
// one channel; a source chasing victims across channels is an attacker tool.
func dxChannelHops(res *dxResult) []dxChanHop {
	per := map[string]map[int]int{} // source → freq → frames
	for _, e := range res.Events {
		if e.FreqMHz == 0 {
			continue
		}
		if per[e.Src] == nil {
			per[e.Src] = map[int]int{}
		}
		per[e.Src][e.FreqMHz]++
	}
	var out []dxChanHop
	for src, fm := range per {
		freqs, total := []int{}, 0
		for f, c := range fm {
			total += c
			if c >= 3 {
				freqs = append(freqs, f)
			}
		}
		// Keep the busiest frequency of each overlap group, then count groups.
		sort.Slice(freqs, func(i, j int) bool { return fm[freqs[i]] > fm[freqs[j]] })
		var reps []int
		for _, f := range freqs {
			distinct := true
			for _, r := range reps {
				if !dxChanDistinct(f, r) {
					distinct = false
					break
				}
			}
			if distinct {
				reps = append(reps, f)
			}
		}
		if len(reps) < 2 {
			continue
		}
		h := dxChanHop{Src: src, Frames: total}
		for _, f := range reps {
			h.Channels = append(h.Channels, freqToChannel(f))
		}
		sort.Ints(h.Channels)
		if bi, ok := res.BSSInfo[src]; ok {
			h.Beacon = bi.Channel
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Channels) != len(out[j].Channels) {
			return len(out[i].Channels) > len(out[j].Channels)
		}
		return out[i].Src < out[j].Src
	})
	return out
}

// dxSparkline renders event density across the capture span as block glyphs.
func dxSparkline(events []dxEvent, width int) string {
	if len(events) == 0 || width < 1 {
		return ""
	}
	t0, t1 := dxEvTime(events[0]), dxEvTime(events[len(events)-1])
	span := t1 - t0
	buckets := make([]int, width)
	for _, e := range events {
		i := 0
		if span > 0 {
			i = int((dxEvTime(e) - t0) / span * float64(width-1))
		}
		buckets[i]++
	}
	peak := 0
	for _, c := range buckets {
		if c > peak {
			peak = c
		}
	}
	glyphs := []rune(" ▁▂▃▄▅▆▇█")
	var sb strings.Builder
	for _, c := range buckets {
		g := 0
		if c > 0 {
			g = 1 + c*(len(glyphs)-2)/peak
		}
		sb.WriteRune(glyphs[g])
	}
	return sb.String()
}

func dxIntsJoin(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}

func dxBuildReport(res *dxResult) *Report {
	rep := newReport(res.Target)
	rep.Summary["Total Frames"] = strconv.Itoa(res.TotalFrames)
	rep.Summary["Deauth Frames"] = strconv.Itoa(res.DeauthN)
	rep.Summary["Disassoc Frames"] = strconv.Itoa(res.DisassocN)
	rep.Summary["Broadcast Deauths"] = strconv.Itoa(res.Broadcast)
	rep.Summary["Peak Rate (fps)"] = fmt.Sprintf("%.1f", res.PeakRate)
	rep.Summary["Rate Window (s)"] = strconv.Itoa(res.WindowSec)
	rep.Summary["Distinct Sources"] = strconv.Itoa(len(res.BySrc))
	rep.Summary["BSSIDs Seen"] = strconv.Itoa(len(res.ByBSSID))
	rep.Summary["Micro-bursts <2ms"] = strconv.Itoa(res.MicroBursts)
	if len(res.SpoofSrc) > 0 {
		rep.Summary["Spoofed Sources"] = strconv.Itoa(len(res.SpoofSrc))
	}
	if res.MinGapMs > 0 {
		rep.Summary["Min Frame Gap"] = fmt.Sprintf("%.2f ms", res.MinGapMs)
	}
	if len(res.Waves) > 0 {
		rep.Summary["Attack Waves"] = strconv.Itoa(len(res.Waves))
		rep.Summary["Attack Span"] = fmt.Sprintf("%.1f s", res.Waves[len(res.Waves)-1].EndSec)
	}
	if res.ProtectedN > 0 {
		rep.Summary["Protected Frames"] = strconv.Itoa(res.ProtectedN)
	}
	if len(res.ByFreq) > 0 {
		chs := []int{}
		for f := range res.ByFreq {
			chs = append(chs, f)
		}
		sort.Ints(chs)
		for i, f := range chs {
			chs[i] = freqToChannel(f)
		}
		rep.Summary["Channels"] = dxIntsJoin(chs)
		bands := []string{}
		for b, n := range res.ByBand {
			bands = append(bands, fmt.Sprintf("%s x%d", b, n))
		}
		sort.Strings(bands)
		rep.Summary["Bands"] = strings.Join(bands, ", ")
	}
	if len(res.Posture) > 0 {
		pc := map[string]int{}
		for _, p := range res.Posture {
			pc[p.PMF]++
		}
		parts := []string{}
		for _, k := range []string{"off", "optional", "required", "in-use", "unknown"} {
			if pc[k] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k, pc[k]))
			}
		}
		rep.Summary["PMF Posture"] = strings.Join(parts, " · ")
	}
	sigMin, sigMax, haveSig := 0, 0, false
	for _, r := range res.RSSI {
		if !haveSig || r.Min < sigMin {
			sigMin = r.Min
		}
		if !haveSig || r.Max > sigMax {
			sigMax = r.Max
		}
		haveSig = true
	}
	if haveSig {
		rep.Summary["Signal Range"] = fmt.Sprintf("%d .. %d dBm", sigMin, sigMax)
	}

	if res.PeakRate >= 10 {
		rep.add(Finding{
			ID: "ODEAUTH-FLOOD", Title: "Deauthentication flood detected", Severity: SevCritical, Score: 9.0,
			Entity: res.Target, Detail: fmt.Sprintf("Peak deauth/disassoc rate of %.1f frames/s far exceeds normal management traffic; consistent with an active denial-of-service.", res.PeakRate),
			Remediation: "Enable 802.11w (PMF); investigate the source MAC; consider WIDS alerting.",
			MITRE:       []string{"T1498", "T1499", "T1557.002"},
		})
	} else if res.PeakRate >= 3 {
		rep.add(Finding{
			ID: "ODEAUTH-ELEVATED", Title: "Elevated deauth activity", Severity: SevHigh, Score: 7.0,
			Entity: res.Target, Detail: fmt.Sprintf("Peak rate %.1f fps suggests targeted deauth bursts.", res.PeakRate),
			Remediation: "Review source and victim MACs; enable PMF.", MITRE: []string{"T1498"},
		})
	}
	if res.Broadcast > 0 {
		rep.add(Finding{
			ID: "ODEAUTH-BROADCAST", Title: "Broadcast deauthentication frames", Severity: SevHigh, Score: 7.5,
			Entity: res.Target, Detail: fmt.Sprintf("%d broadcast deauths (ff:ff:ff:ff:ff:ff) observed; these disconnect all clients of a BSS at once.", res.Broadcast),
			Remediation: "PMF prevents broadcast deauth spoofing; enable WPA3 or 802.11w.", MITRE: []string{"T1498", "T1557.002"},
		})
	}
	// Machine-speed cadence — a strong injection signature independent of volume.
	if res.MicroBursts >= 10 {
		rep.add(Finding{
			ID: "ODEAUTH-INJECT", Title: "Machine-speed deauth bursts (injection signature)", Severity: SevHigh, Score: 7.5,
			Entity:      res.Target,
			Detail:      fmt.Sprintf("%d adjacent frame pairs arrived under 2 ms apart (min gap %.2f ms). Hand-driven stations do not emit deauth/disassoc at this cadence; the pattern is characteristic of tool-driven management-frame injection.", res.MicroBursts, res.MinGapMs),
			Remediation: "Enable 802.11w (PMF) so spoofed management frames are rejected; locate the transmitter with WIDS / spectrum tooling.",
			MITRE:       []string{"T1498", "T1557.002"},
		})
	}
	// A single addressed client taking a sustained, targeted disconnect storm.
	if res.TopVictim != "" && res.TopVictimN >= 15 {
		ctx := ""
		for _, l := range res.Links { // Links are sorted; first match = dominant BSS
			if l.Victim == res.TopVictim {
				ctx = fmt.Sprintf(" on BSS %s, predominantly sourced from %s (vendor %s)", l.BSSID, l.TopSrc, lookupVendorStr(l.TopSrc))
				break
			}
		}
		rep.add(Finding{
			ID: "ODEAUTH-VICTIM", Title: "Targeted client disconnect storm", Severity: SevHigh, Score: 7.0,
			Entity:      res.TopVictim,
			Detail:      fmt.Sprintf("Client %s (vendor %s) received %d addressed deauth/disassoc frames%s — a sustained, targeted disconnect rather than incidental management traffic.", res.TopVictim, lookupVendorStr(res.TopVictim), res.TopVictimN, ctx),
			Remediation: "Confirm whether the client roamed legitimately; if not, treat as a targeted DoS and enable PMF.",
			MITRE:       []string{"T1498"},
		})
	}
	// Reason-code profile corroborating spoofing (informational on its own).
	if total := res.DeauthN + res.DisassocN; total > 0 {
		if r7 := res.ByReason[7]; r7 > 0 && float64(r7)/float64(total) >= 0.5 {
			rep.add(Finding{
				ID: "ODEAUTH-REASON7", Title: "Reason-code profile matches common deauth tools", Severity: SevInfo, Score: 1.0,
				Entity:      res.Target,
				Detail:      fmt.Sprintf("%d of %d frames carry reason 7 (Class 3 frame from non-associated STA), the default many off-the-shelf deauth utilities emit. Not conclusive alone, but it corroborates spoofing when paired with burst or volume signals.", r7, total),
				Remediation: "Weigh alongside the peak-rate and micro-burst findings; benign roaming rarely concentrates on a single reason code.",
				MITRE:       []string{"T1557.002"},
			})
		}
	}
	// top attackers
	for _, kv := range dxTopN(res.BySrc, 5) {
		if kv.v >= 5 {
			rep.add(Finding{
				ID: "ODEAUTH-SOURCE", Title: "High-volume deauth source", Severity: SevMedium, Score: 5.5,
				Entity: kv.k, Detail: fmt.Sprintf("Source %s transmitted %d deauth/disassoc frames (vendor %s).", kv.k, kv.v, lookupVendorStr(kv.k)),
				Remediation: "Correlate with rogue AP / attacker toolkit; block at WIPS.", MITRE: []string{"T1498"},
			})
		}
	}
	// MAC-spoof detection via 802.11 sequence-number behaviour. Independent of
	// volume/cadence: it catches impersonation even at a low frame rate.
	for _, s := range res.SpoofSrc {
		if s.Verdict == "static" {
			rep.add(Finding{
				ID: "ODEAUTH-SPOOF-SEQSTATIC", Title: "Spoofed source MAC (frozen sequence counter)", Severity: SevHigh, Score: 8.0,
				Entity: s.Src,
				Detail: fmt.Sprintf("Source %s (vendor %s) sent %d non-retransmitted deauth/disassoc frames that share sequence number %d (%.0f%% identical). A genuine 802.11 transmitter increments its sequence counter per frame; a frozen counter is a hallmark of tool-driven injection spoofing this source address.",
					s.Src, lookupVendorStr(s.Src), s.Frames, s.TopSeq, s.TopShare*100),
				Remediation: "Treat the source MAC as impersonated; enable 802.11w (PMF) so spoofed management frames are rejected, and locate the transmitter with WIDS.",
				MITRE:       []string{"T1557.002", "T1498"},
			})
		} else {
			rep.add(Finding{
				ID: "ODEAUTH-SPOOF-SEQANOM", Title: "Spoofed source MAC (incoherent sequence stream)", Severity: SevHigh, Score: 7.5,
				Entity: s.Src,
				Detail: fmt.Sprintf("Source %s (vendor %s): %d frames carry only %d distinct sequence numbers with %.0f%% of adjacent frames stepping the counter backward. A single genuine radio cannot produce this; the pattern indicates the MAC is impersonated by a separate injector running alongside the real station.",
					s.Src, lookupVendorStr(s.Src), s.Frames, s.Distinct, s.RegShare*100),
				Remediation: "Correlate against the genuine AP's live sequence counter; enable PMF and raise a WIPS alert on the impersonated BSSID.",
				MITRE:       []string{"T1557.002", "T1498"},
			})
		}
	}
	// Correlation: a single source MAC transmitting under multiple BSSIDs.
	for _, mb := range res.MultiBSSID {
		sev, score := SevMedium, 5.5
		if len(mb.BSSIDs) >= 3 {
			sev, score = SevHigh, 7.5
		}
		rep.add(Finding{
			ID: "ODEAUTH-MULTIBSS", Title: "Source MAC spans multiple BSSIDs", Severity: sev, Score: score,
			Entity: mb.Src,
			Detail: fmt.Sprintf("Source %s (vendor %s) transmitted %d deauth/disassoc frames under %d distinct BSSIDs (%s). A legitimate access point owns a single BSSID; one source addressing several BSSes is consistent with a rogue injector spraying multiple networks or spoofing several APs.",
				mb.Src, lookupVendorStr(mb.Src), mb.Frames, len(mb.BSSIDs), strings.Join(mb.BSSIDs, ", ")),
			Remediation: "Treat the source as a rogue injector; locate it with WIDS and enable PMF on the affected BSSes.",
			MITRE:       []string{"T1557.002", "T1498"},
		})
	}
	// Two transmitters behind one MAC: the signal splits into interleaved bands.
	for _, r := range res.RSSI {
		if !r.Split {
			continue
		}
		rep.add(Finding{
			ID: "ODEAUTH-SPOOF-RSSI", Title: "Spoofed source MAC (two signal bands)", Severity: SevHigh, Score: 7.5,
			Entity: r.Src,
			Detail: fmt.Sprintf("Frames from %s (vendor %s) arrive in two separate signal bands — %d frames near %.0f dBm and %d near %.0f dBm (gap %d dB) — switching between them %d times. One stationary radio holds a single band; interleaved bands mean a second transmitter is impersonating this address.",
				r.Src, lookupVendorStr(r.Src), r.HighN, r.HighMean, r.LowN, r.LowMean, r.Gap, r.Transitions),
			Remediation: "The weaker or stronger band (whichever is not the known device) is the impersonator; locate it by signal with WIDS, and enable PMF so its frames are rejected.",
			MITRE:       []string{"T1557.002", "T1498"},
		})
	}
	// 802.11w posture of each targeted BSS — the deciding factor in whether the
	// observed frames actually disconnect anyone. Capped to the 5 busiest BSSes.
	for i, p := range res.Posture {
		if i >= 5 {
			break
		}
		name := p.BSSID
		if p.SSID != "" {
			name = fmt.Sprintf("%s (%q, %s)", p.BSSID, p.SSID, p.Security)
		}
		switch {
		case p.PMF == "off":
			rep.add(Finding{
				ID: "ODEAUTH-PMF-OFF", Title: "Targeted BSS has no 802.11w protection", Severity: SevHigh, Score: 7.0,
				Entity:      p.BSSID,
				Detail:      fmt.Sprintf("BSS %s received %d deauth/disassoc frames and does not support Protected Management Frames (%s). Its clients accept unauthenticated deauths, so the observed frames are effective disconnects.", name, p.Frames, p.Basis),
				Remediation: "Enable 802.11w: set PMF to required (WPA3-SAE mandates it); on WPA2 set at least 'optional'. Move open networks to OWE.",
				MITRE:       []string{"T1498", "T1557.002"},
			})
		case p.PMF == "optional" && p.Unprotected > 0:
			rep.add(Finding{
				ID: "ODEAUTH-PMF-OPTIONAL", Title: "PMF optional on targeted BSS", Severity: SevMedium, Score: 5.0,
				Entity:      p.BSSID,
				Detail:      fmt.Sprintf("BSS %s advertises PMF as capable but not required (%s). Clients that negotiated PMF drop the %d unprotected frames observed; legacy clients without PMF are still disconnected.", name, p.Basis, p.Unprotected),
				Remediation: "Set PMF to required once all clients support it (or split legacy clients onto a separate SSID).",
				MITRE:       []string{"T1498"},
			})
		case p.PMF == "required" && p.Unprotected > 0:
			rep.add(Finding{
				ID: "ODEAUTH-PMF-FORGED", Title: "Forged deauths against a PMF-required BSS", Severity: SevLow, Score: 3.0,
				Entity:      p.BSSID,
				Detail:      fmt.Sprintf("BSS %s requires PMF (%s), yet %d unprotected deauth/disassoc frames were sent under its BSSID. A PMF-required AP never sends these unprotected, so they are forged; associated clients discard them and the attack is mitigated.", name, p.Basis, p.Unprotected),
				Remediation: "No client impact expected; still locate the source, since the attempt shows hostile intent on this network.",
				MITRE:       []string{"T1557.002"},
			})
		}
	}
	// Recurring waves: an attacker returning after silence, not one burst.
	if len(res.Waves) >= 3 {
		rep.add(Finding{
			ID: "ODEAUTH-WAVES", Title: "Recurring deauth attack waves", Severity: SevMedium, Score: 5.0,
			Entity:      res.Target,
			Detail:      fmt.Sprintf("Activity came in %d separate waves (gaps over %d s of silence) across %.1f s. Repeated bursts point to a persistent or scripted attacker rather than a one-off event.", len(res.Waves), res.WaveGap, res.Waves[len(res.Waves)-1].EndSec),
			Remediation: "Use the wave timestamps to line up with WIDS/AP logs and physical access records; enable PMF.",
			MITRE:       []string{"T1498"},
		})
	}
	// Channel hopping: one source chasing victims across non-overlapping channels.
	for _, h := range res.ChanHops {
		bc := ""
		if h.Beacon > 0 {
			bc = fmt.Sprintf(" Its BSS advertises channel %d, so frames on the other channels are off-channel.", h.Beacon)
		}
		rep.add(Finding{
			ID: "ODEAUTH-CHANHOP", Title: "Deauth source hops channels", Severity: SevMedium, Score: 6.0,
			Entity:      h.Src,
			Detail:      fmt.Sprintf("Source %s (vendor %s) sent %d deauth/disassoc frames across %d non-overlapping channels (%s). An access point radio stays on one channel; a source following victims across channels is behaving like an attack tool.%s", h.Src, lookupVendorStr(h.Src), h.Frames, len(h.Channels), dxIntsJoin(h.Channels), bc),
			Remediation: "Treat the source as hostile; enable PMF on every band and correlate with WIDS sensors on each channel.",
			MITRE:       []string{"T1498", "T1557.002"},
		})
	}
	rep.Data = struct {
		Waves    []dxWave       `json:"waves"`
		Posture  []dxPosture    `json:"pmf_posture"`
		RSSI     []dxRSSIStat   `json:"signal_by_source,omitempty"`
		Freqs    map[int]int    `json:"frames_by_freq_mhz,omitempty"`
		Bands    map[string]int `json:"frames_by_band,omitempty"`
		ChanHops []dxChanHop    `json:"channel_hops,omitempty"`
	}{res.Waves, res.Posture, res.RSSI, res.ByFreq, res.ByBand, res.ChanHops}
	rep.TextBody = dxTextBody(res)
	return rep
}

// dxHasFinding reports whether a report contains a finding with the given ID.
func dxHasFinding(rep *Report, id string) bool {
	for _, f := range rep.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func lookupVendorStr(mac string) string {
	b, err := parseMAC(mac)
	if err != nil {
		return "Unknown"
	}
	return lookupVendor(b)
}

type kvp struct {
	k string
	v int
}

func dxTopN(m map[string]int, n int) []kvp {
	out := []kvp{}
	for k, v := range m {
		out = append(out, kvp{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func dxTextBody(res *dxResult) string {
	var sb strings.Builder
	sb.WriteString("REASON CODE DISTRIBUTION\n")
	codes := []int{}
	for c := range res.ByReason {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		sb.WriteString(fmt.Sprintf("  %3d  %-45s x%d\n", c, dxReason(c), res.ByReason[c]))
	}
	sb.WriteString("\nTOP SOURCES\n")
	for _, kv := range dxTopN(res.BySrc, 10) {
		sb.WriteString(fmt.Sprintf("  %-18s %-14s x%d\n", kv.k, lookupVendorStr(kv.k), kv.v))
	}
	sb.WriteString("\nTOP VICTIMS\n")
	for _, kv := range dxTopN(res.ByVictim, 10) {
		sb.WriteString(fmt.Sprintf("  %-18s x%d\n", kv.k, kv.v))
	}
	sb.WriteString("\nTARGETING MAP (BSS -> victim <- source)\n")
	if len(res.Links) == 0 {
		sb.WriteString("  (no addressed victims; traffic was broadcast-only)\n")
	}
	for i, l := range res.Links {
		if i >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-18s -> %-18s <- %-18s x%d\n", l.BSSID, l.Victim, l.TopSrc, l.Count))
	}
	if len(res.Waves) > 0 {
		sb.WriteString(fmt.Sprintf("\nATTACK TIMELINE (%d wave(s), split on >%ds silence)\n", len(res.Waves), res.WaveGap))
		sb.WriteString("  |" + dxSparkline(res.Events, 48) + "|\n")
		for i, w := range res.Waves {
			if i >= 15 {
				sb.WriteString(fmt.Sprintf("  ... %d more wave(s) in JSON export\n", len(res.Waves)-i))
				break
			}
			ch := ""
			if len(w.Channels) > 0 {
				ch = "  ch " + dxIntsJoin(w.Channels)
			}
			sb.WriteString(fmt.Sprintf("  #%-2d +%7.1fs -> +%7.1fs  %6.1fs  %5d fr  %6.1f fps  bcast %-4d src %s  rsn %d%s\n",
				w.N, w.StartSec, w.EndSec, w.Duration, w.Frames, w.Rate, w.Broadcast, w.TopSrc, w.TopReason, ch))
		}
	}
	if len(res.ByFreq) > 0 {
		sb.WriteString("\nCHANNELS / BANDS\n")
		fs := []int{}
		for f := range res.ByFreq {
			fs = append(fs, f)
		}
		sort.Ints(fs)
		for _, f := range fs {
			sb.WriteString(fmt.Sprintf("  ch %-4d %-7s %5d MHz  x%d\n", freqToChannel(f), bandForFreq(f), f, res.ByFreq[f]))
		}
		for _, h := range res.ChanHops {
			sb.WriteString(fmt.Sprintf("  hop: %-18s across ch %s (%d frames)\n", h.Src, dxIntsJoin(h.Channels), h.Frames))
		}
	}
	if len(res.RSSI) > 0 {
		sb.WriteString("\nSIGNAL BY SOURCE (dBm)\n")
		for i, r := range res.RSSI {
			if i >= 10 {
				break
			}
			note := ""
			if r.Split {
				note = fmt.Sprintf("  SPLIT %.0f / %.0f dBm, %d switches", r.HighMean, r.LowMean, r.Transitions)
			}
			sb.WriteString(fmt.Sprintf("  %-18s n=%-5d min %4d  mean %6.1f  max %4d%s\n", r.Src, r.Samples, r.Min, r.Mean, r.Max, note))
		}
	}
	if len(res.Posture) > 0 {
		sb.WriteString("\nPMF / 802.11w POSTURE (targeted BSSes)\n")
		for i, p := range res.Posture {
			if i >= 10 {
				break
			}
			ssid := p.SSID
			if ssid == "" {
				ssid = "-"
			}
			sb.WriteString(fmt.Sprintf("  %-18s %-16s %-15s PMF %-8s unprot %-5d prot %-5d (%s)\n",
				p.BSSID, truncStr(ssid, 16), p.Security, p.PMF, p.Unprotected, p.Protected, p.Basis))
		}
	}
	return sb.String()
}

// ---- frame crafting (lab) -------------------------------------------------

func dxBuildDeauth(dst, src, bssid []byte, reason int, disassoc bool) []byte {
	return dxBuildDeauthSeq(dst, src, bssid, reason, disassoc, 0, false)
}

// dxBuildDeauthSeq crafts a deauth/disassoc frame with an explicit sequence
// number and retry bit, so tests can model both a genuine incrementing counter
// and a frozen injector.
func dxBuildDeauthSeq(dst, src, bssid []byte, reason int, disassoc bool, seq int, retry bool) []byte {
	var f []byte
	fc0 := byte(0xc0) // deauth
	if disassoc {
		fc0 = 0xa0
	}
	fc1 := byte(0x00)
	if retry {
		fc1 |= 0x08 // retry bit (frame-control bit 11)
	}
	f = append(f, fc0, fc1)
	f = append(f, 0x00, 0x00) // duration
	f = append(f, dst...)
	f = append(f, src...)
	f = append(f, bssid...)
	sc := make([]byte, 2) // sequence control: seq in high 12 bits, frag=0
	binary.LittleEndian.PutUint16(sc, uint16(seq<<4))
	f = append(f, sc...)
	rb := make([]byte, 2)
	binary.LittleEndian.PutUint16(rb, uint16(reason))
	f = append(f, rb...)
	return f
}

func dxWrapPcap(frames [][]byte, tsBase uint32, usecStep uint32) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(DLT_IEEE802_11))
	b = append(b, hdr...)
	t := tsBase
	us := uint32(0)
	for _, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], t)
		binary.LittleEndian.PutUint32(rec[4:8], us)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		b = append(b, rec...)
		b = append(b, fr...)
		us += usecStep
		if us >= 1000000 {
			t += us / 1000000
			us = us % 1000000
		}
	}
	return b
}

// dxWrapRadiotap wraps frames in a radiotap pcap (DLT 127). Each frame gets
// its own time offset (seconds from tsBase), channel frequency and signal, so
// synthetic captures can exercise the timeline, channel and RSSI analysis.
func dxWrapRadiotap(frames [][]byte, offs []float64, freqs, sigs []int, tsBase uint32) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(DLT_RADIOTAP))
	b = append(b, hdr...)
	for i, fr := range frames {
		// version, pad, len=13, present = Channel(bit 3) | dBm signal(bit 5)
		rt := []byte{0x00, 0x00, 13, 0x00, 0x28, 0x00, 0x00, 0x00}
		rt = binary.LittleEndian.AppendUint16(rt, uint16(freqs[i]))
		rt = binary.LittleEndian.AppendUint16(rt, 0x0080) // 2 GHz spectrum flag
		rt = append(rt, byte(int8(sigs[i])))
		us := uint64(math.Round(offs[i] * 1e6))
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], tsBase+uint32(us/1000000))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(us%1000000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(rt)+len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(rt)+len(fr)))
		b = append(b, rec...)
		b = append(b, rt...)
		b = append(b, fr...)
	}
	return b
}

// dxSynthCapture builds the demo capture: a WPA2 AP without PMF beaconing on
// channel 6, and an injector spoofing that AP's MAC with a frozen sequence
// counter. The injector sits far from the sensor (~-71 dBm) while the genuine
// AP's own frames arrive strong (~-43 dBm), interleaved — two signal bands on
// one MAC. The attack comes in three waves; the last moves to channel 11.
func dxSynthCapture() []byte {
	bssid := []byte{0x00, 0x1a, 0x2b, 0xaa, 0xbb, 0xcc}
	victim := []byte{0x3c, 0x07, 0x54, 0x11, 0x22, 0x33}
	bcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	jitter := []int{0, 1, -1, 2, -2}
	var frames [][]byte
	var offs []float64
	var freqs, sigs []int
	add := func(fr []byte, t float64, freq, sig int) {
		frames = append(frames, fr)
		offs = append(offs, t)
		freqs = append(freqs, freq)
		sigs = append(sigs, sig)
	}
	add(craftBeaconSec(bssid, "OwlLab-Corp", 6, "WPA2-PSK"), 0, 2437, -42)
	// Wave 1: 60 broadcast deauths reason 7 from the injector, with 15 targeted
	// reason-2 deauths at the victim from the genuine AP woven in, ~1.5 ms apart
	// — a machine-speed flood that also exercises the micro-burst detector.
	t := 0.1
	targeted := 0
	for i := 0; i < 75; i++ {
		if i%5 == 4 && targeted < 15 {
			add(dxBuildDeauth(victim, bssid, bssid, 2, false), t, 2437, -43+jitter[i%5])
			targeted++
		} else {
			add(dxBuildDeauth(bcast, bssid, bssid, 7, false), t, 2437, -71+jitter[i%5])
		}
		t += 0.0015
	}
	// a legit disassoc reason 8 from the AP
	add(dxBuildDeauth(victim, bssid, bssid, 8, true), t, 2437, -43)
	// Waves 2 and 3 after 20 s of silence each; wave 3 hops to channel 11.
	for w, freq := range []int{2437, 2462} {
		t = 20.0 * float64(w+1)
		for i := 0; i < 20; i++ {
			add(dxBuildDeauth(bcast, bssid, bssid, 7, false), t, freq, -71+jitter[i%5])
			t += 0.0015
		}
	}
	return dxWrapRadiotap(frames, offs, freqs, sigs, uint32(time.Now().Unix()))
}

// dxSelfTest exercises the parser, analyzer and detector against crafted and
// synthetic inputs. It returns (pass, fail) counts and prints one line each.
func dxSelfTest() (int, int) {
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg("FAIL: " + name)
		}
	}
	if b, err := parseMAC("3c:07:54:11:22:33"); err == nil {
		check("parseMAC/macStr round-trip", macStr(b) == "3c:07:54:11:22:33")
	} else {
		check("parseMAC basic", false)
	}
	check("macIsBroadcast(ff:...)", macIsBroadcast([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
	check("vendor OUI lookup (Cisco)", lookupVendorStr("00:1a:2b:aa:bb:cc") == "Cisco")
	check("reason 7 text", dxReason(7) == "Class 3 frame from non-associated STA")
	check("reason unknown fallback", strings.Contains(dxReason(250), "250"))

	fr := dxBuildDeauth(
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x00, 0x1a, 0x2b, 0xaa, 0xbb, 0xcc},
		[]byte{0x00, 0x1a, 0x2b, 0xaa, 0xbb, 0xcc}, 7, false)
	if f, err := parseDot11(fr); err == nil {
		check("parseDot11 type=Management", f.Type == TypeMgmt)
		check("parseDot11 subtype=Deauth", f.Subtype == MgmtDeauth)
		check("deauth reason round-trip", len(f.Body) >= 2 && int(binary.LittleEndian.Uint16(f.Body[0:2])) == 7)
	} else {
		check("parseDot11 crafted deauth", false)
	}

	rt := []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, payload := parseRadiotap(append(rt, fr...)); true {
		check("radiotap header stripped", len(payload) == len(fr))
	}

	g, n := dxBurstMetrics([]dxEvent{{TsSec: 1, TsUsec: 0}, {TsSec: 1, TsUsec: 1000}})
	check("dxBurstMetrics gap in ms", g > 0.9 && g < 1.1 && n == 1)

	check("dxSeqDelta wraps 4095->0 forward", dxSeqDelta(4095, 0) == 1)
	check("dxSeqDelta detects regression", dxSeqDelta(100, 90) == -10)
	{
		// A frozen counter is spoofed; a monotonically incrementing counter is
		// a genuine station and must not be flagged.
		var spoof, legit []dxEvent
		for i := 0; i < 20; i++ {
			spoof = append(spoof, dxEvent{Src: "aa:aa:aa:aa:aa:aa", Seq: 0})
			legit = append(legit, dxEvent{Src: "bb:bb:bb:bb:bb:bb", Seq: 100 + i})
		}
		ss := dxSeqAnalysis(spoof)
		check("seq-analysis flags frozen counter", len(ss) == 1 && ss[0].Verdict == "static")
		check("seq-analysis clears incrementing counter", len(dxSeqAnalysis(legit)) == 0)
		// Retries legitimately repeat the counter and must be ignored.
		var retries []dxEvent
		for i := 0; i < 20; i++ {
			retries = append(retries, dxEvent{Src: "cc:cc:cc:cc:cc:cc", Seq: 7, Retry: true})
		}
		check("seq-analysis ignores retransmissions", len(dxSeqAnalysis(retries)) == 0)
	}
	{
		// Victim↔BSSID correlation: the heaviest (BSS,victim) pair surfaces,
		// and a source hitting two BSSIDs (≥3 frames each) is flagged.
		var ev []dxEvent
		for i := 0; i < 6; i++ {
			ev = append(ev, dxEvent{Src: "b1", Dst: "v1", BSSID: "b1"})
		}
		for i := 0; i < 4; i++ {
			ev = append(ev, dxEvent{Src: "s9", Dst: "v2", BSSID: "b1"})
			ev = append(ev, dxEvent{Src: "s9", Dst: "v3", BSSID: "b2"})
		}
		r := &dxResult{ByBSSID: map[string]int{}, Events: ev}
		dxCorrelate(r)
		check("correlate surfaces top victim link", len(r.Links) > 0 && r.Links[0].Victim == "v1" && r.Links[0].BSSID == "b1" && r.Links[0].TopSrc == "b1")
		check("correlate flags multi-BSSID source", len(r.MultiBSSID) == 1 && r.MultiBSSID[0].Src == "s9" && len(r.MultiBSSID[0].BSSIDs) == 2)
	}

	{
		// RSSI split: two interleaved bands are flagged; a client walking away
		// (one gradual shift) and a steady radio are not.
		var split, walk, steady []dxEvent
		for i := 0; i < 30; i++ {
			sig := -70
			if i%3 == 0 {
				sig = -40
			}
			split = append(split, dxEvent{Src: "aa", Signal: sig, HasSignal: true})
			walk = append(walk, dxEvent{Src: "bb", Signal: -40 - i*2, HasSignal: true})
			steady = append(steady, dxEvent{Src: "cc", Signal: -55 + i%3, HasSignal: true})
		}
		rs := dxRSSIAnalysis(split)
		check("rssi flags interleaved signal bands", len(rs) == 1 && rs[0].Split)
		check("rssi clears client walking away", !dxRSSIAnalysis(walk)[0].Split)
		check("rssi clears steady radio", !dxRSSIAnalysis(steady)[0].Split)
	}
	{
		ev := []dxEvent{{TsSec: 0}, {TsSec: 0, TsUsec: 100000}, {TsSec: 10}, {TsSec: 10, TsUsec: 100000}, {TsSec: 30}}
		w := dxWaves(ev, 5)
		check("waves split on silence gaps", len(w) == 3 && w[0].Frames == 2 && w[2].Frames == 1)
		check("wave offsets relative to start", len(w) == 3 && w[1].StartSec == 10 && w[2].StartSec == 30)
	}
	check("2.4GHz overlapping channels merge (6/7)", !dxChanDistinct(2437, 2442))
	check("2.4GHz non-overlapping channels distinct (1/6)", dxChanDistinct(2412, 2437))
	check("5GHz channels distinct (36/40)", dxChanDistinct(5180, 5200))
	{
		ap := []byte{0x00, 0x1a, 0x2b, 0x01, 0x02, 0x03}
		f3, _ := parseDot11(craftBeaconSec(ap, "sae", 36, "WPA3-SAE"))
		f2, _ := parseDot11(craftBeaconSec(ap, "psk", 6, "WPA2-PSK"))
		b3, ok3 := dxParseBSSInfo(f3)
		b2, ok2 := dxParseBSSInfo(f2)
		check("beacon RSN: WPA3-SAE requires PMF", ok3 && b3.MFPReq && b3.Security == "WPA3-SAE")
		check("beacon RSN: WPA2-PSK without PMF", ok2 && !b2.MFPCap && b2.Channel == 6)
		// 6 GHz without a beacon still implies mandatory PMF.
		r := &dxResult{BSSInfo: map[string]dxBSSInfo{}, Events: []dxEvent{{BSSID: "b6", FreqMHz: 5975}}}
		p := dxPMFPosture(r)
		check("6 GHz BSS posture = PMF required", len(p) == 1 && p[0].PMF == "required" && p[0].Unprotected == 1)
	}
	{
		// A protected deauth keeps its encrypted reason out of the histogram.
		fr := dxBuildDeauth([]byte{1, 2, 3, 4, 5, 6}, []byte{0, 0x1a, 0x2b, 1, 1, 1}, []byte{0, 0x1a, 0x2b, 1, 1, 1}, 7, false)
		fr[1] |= 0x40 // protected-frame bit
		if cf, err := parseCaptureBytes(dxWrapPcap([][]byte{fr}, 1, 0)); err == nil {
			r := dxAnalyzeCap(cf, "pmf")
			check("protected deauth counted, reason skipped", r.ProtectedN == 1 && len(r.ByReason) == 0)
		} else {
			check("protected deauth capture parse", false)
		}
	}

	if cf, err := parseCaptureBytes(dxSynthCapture()); err == nil {
		res := dxAnalyzeCap(cf, "selftest")
		check("analyzer counts deauths", res.DeauthN >= 75)
		check("analyzer sees broadcast deauth", res.Broadcast >= 60)
		check("flood peak-rate detected", res.PeakRate >= 10)
		check("micro-bursts flagged", res.MicroBursts >= 10)
		rep := dxBuildReport(res)
		rep.computeGrade()
		check("flood finding emitted", dxHasFinding(rep, "ODEAUTH-FLOOD"))
		check("broadcast finding emitted", dxHasFinding(rep, "ODEAUTH-BROADCAST"))
		check("injection finding emitted", dxHasFinding(rep, "ODEAUTH-INJECT"))
		check("mac-spoof finding emitted", dxHasFinding(rep, "ODEAUTH-SPOOF-SEQSTATIC"))
		check("correlation builds targeting links", len(res.Links) >= 1)
		check("single BSSID seen in synth", len(res.ByBSSID) == 1)
		check("radiotap signal read per frame", len(res.RSSI) == 1 && res.RSSI[0].Samples == res.DeauthN+res.DisassocN)
		check("beacon posture recorded (PMF off)", len(res.Posture) == 1 && res.Posture[0].PMF == "off" && res.Posture[0].SSID == "OwlLab-Corp")
		check("three attack waves found", len(res.Waves) == 3)
		check("channel hop 6 -> 11 found", len(res.ChanHops) == 1 && dxIntsJoin(res.ChanHops[0].Channels) == "6, 11")
		check("rssi-spoof finding emitted", dxHasFinding(rep, "ODEAUTH-SPOOF-RSSI"))
		check("pmf-off finding emitted", dxHasFinding(rep, "ODEAUTH-PMF-OFF"))
		check("waves finding emitted", dxHasFinding(rep, "ODEAUTH-WAVES"))
		check("chanhop finding emitted", dxHasFinding(rep, "ODEAUTH-CHANHOP"))
		check("grade below A (findings present)", rep.Grade != "A+" && rep.Grade != "A")
	} else {
		check("synthetic capture parse", false)
	}
	return pass, fail
}

// ---- lab generator action -------------------------------------------------

func dxShowReasonTable() {
	sectionHeader("802.11 Reason Codes")
	codes := []int{}
	for c := range dxReasonCodes {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	rows := [][]string{}
	for _, c := range codes {
		rows = append(rows, []string{strconv.Itoa(c), dxReasonCodes[c]})
	}
	table([]string{"CODE", "MEANING"}, rows)
}

func dxCraftLab() {
	sectionHeader("Deauth Frame Lab (offline crafting)")
	warnMsg("Crafted frames are written to a pcap for lab replay ONLY in an")
	warnMsg("authorized, isolated environment. This build does not transmit.")
	reason := dxFlagReason
	if reason == 0 {
		reason = 7
	}
	bssid := []byte{0x00, 0x1a, 0x2b, 0xaa, 0xbb, 0xcc}
	victim := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := dxBuildDeauth(victim, bssid, bssid, reason, false)
	fmt.Println()
	kvRow("Subtype", "Deauthentication (0x0C)")
	kvRow("Reason", fmt.Sprintf("%d — %s", reason, dxReason(reason)))
	kvRow("BSSID", macStr(bssid))
	kvRow("Length", strconv.Itoa(len(frame))+" bytes")
	fmt.Println()
	fmt.Println(col("  Hex frame:", DR))
	fmt.Println(hexDumpBlock(frame, len(frame)))
}

func dxAnalyzePath(path string) (*Report, error) {
	cf, err := loadCapture(path)
	if err != nil {
		return nil, err
	}
	res := dxAnalyzeCap(cf, filepath.Base(path))
	return dxBuildReport(res), nil
}

func dxDemoReport() *Report {
	cf, err := parseCaptureBytes(dxSynthCapture())
	if err != nil {
		r := newReport("synthetic-demo")
		r.add(Finding{Title: "demo error", Detail: err.Error(), Severity: SevInfo})
		return r
	}
	res := dxAnalyzeCap(cf, "synthetic-demo")
	return dxBuildReport(res)
}

func dxHowto() []howSection {
	notes := append(legalWarningLines(),
		"",
		"Transmitting deauthentication frames against networks you do not",
		"own or control is a DoS attack and is illegal without authorization.")
	return []howSection{
		{"LEGAL & ETHICAL WARNING", notes},
		{"HOW TO USE", []string{
			"ODeauth analyzes captures for deauth/disassoc floods and provides an",
			"offline frame-dissection lab for authorized testing.",
			"",
			"1. Detector:  ODeauth --input capture.pcap",
			"2. Review peak rate, broadcast deauths, micro-bursts, sources, victims,",
			"   attack waves, channels, signal per source and PMF posture.",
			"3. Reason table:  menu → 'Reason code reference'.",
			"4. Lab view:  ODeauth --reason 7   then menu → 'Deauth frame lab'.",
			"5. Export:  --format sarif --output deauth.sarif",
			"6. Validate:  ODeauth --input capture.pcap --validate   (exit 0/1).",
			"7. Self-test: ODeauth --selftest   |   Demo: ODeauth --demo.",
		}},
		{"REQUIREMENTS", []string{
			"- A pcap/pcapng containing 802.11 management frames.",
			"- Offline only: no radio transmission is performed.",
			"- --reason N selects the reason code used by the lab builder.",
		}},
		{"PROTOCOL NOTES", []string{
			"- Deauth subtype 0x0C, disassoc 0x0A, both carry a 2-byte reason.",
			"- Flood detection uses a sliding peak rate (--window N seconds).",
			"- Micro-burst detection flags frame pairs under 2 ms apart, the",
			"  cadence of tool-driven injection rather than hand-driven clients.",
			"- MAC-spoof detection reads the 802.11 sequence counter: a genuine",
			"  radio increments it per frame, so a frozen or incoherent stream",
			"  from one source MAC exposes an impersonated address.",
			"- Victim↔BSSID correlation maps each targeted client to its BSS and",
			"  attacking source; a source spanning multiple BSSIDs is a rogue tell.",
			"- RSSI spoof detection: one MAC whose frames split into two",
			"  interleaved signal bands has two transmitters behind it.",
			"- PMF posture reads each targeted BSS's beacon (RSN MFPC/MFPR):",
			"  without 802.11w the deauths work; with PMF required they are forged.",
			"- Attack timeline groups frames into waves (--wave-gap N seconds).",
			"- Channel analysis maps frames to channel/band from radiotap and",
			"  flags a source on non-overlapping channels (overlap-aware on 2.4GHz).",
			"- Broadcast deauth (ff:ff:...) disconnects an entire BSS at once.",
			"- 802.11w (PMF) cryptographically protects these frames.",
		}},
	}
}

func dxActions() []menuAction {
	return []menuAction{
		{"Analyze capture (flood detector)", "Scan a pcap/pcapng for deauth floods", analyzeInteractive},
		{"Run synthetic demo", "Built-in sample flood, no capture needed", runDemoInteractive},
		{"Reason code reference", "IEEE 802.11 deauth/disassoc reason table", dxShowReasonTable},
		{"Deauth frame lab (offline)", "Dissect a crafted frame, no transmission", dxCraftLab},
		{"Show last report", "Re-display the most recent analysis", showLastReport},
		{"Export report", "Write txt/md/json/csv/sarif to a file", interactiveExport},
	}
}

func dxRegisterFlags(fs *flag.FlagSet) {
	fs.IntVar(&dxFlagReason, "reason", 7, "reason code for the deauth lab builder")
	fs.IntVar(&dxFlagWindow, "window", 1, "sliding window (seconds) for flood rate")
	fs.IntVar(&dxFlagWaveGap, "wave-gap", 5, "silence (seconds) that separates attack waves")
}

func dxUsageExtra() {
	fmt.Println("      --reason N        Reason code for the offline deauth lab (default 7)")
	fmt.Println("      --window N        Flood-rate sliding window in seconds (default 1)")
	fmt.Println("      --wave-gap N      Silence in seconds that splits attack waves (default 5)")
}

func init() {
	hookHowto = dxHowto
	hookDemo = dxDemoReport
	hookAnalyze = dxAnalyzePath
	hookActions = dxActions
	hookRegisterFlags = dxRegisterFlags
	hookUsageExtra = dxUsageExtra
	hookSelfTest = dxSelfTest
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODeauth reads Wi-Fi capture files (pcap / pcapng) offline and detects deauthentication and disassociation attacks. It measures the peak frame rate, broadcast deauths and micro-bursts, and identifies the attacking sources and the victims. It also flags spoofed MAC addresses (sequence numbers and two signal levels from one MAC), checks whether the network uses PMF (802.11w), groups frames into attack waves and maps them to channels.",
	"It never transmits anything. It only reads files you give it.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Start with [01] and give it a capture file, or try [02] to see a full example without one. Every screen ends with \"Press Enter to continue\" and returns here. [H] opens this help, [0] or q quits.",
	"The capture must contain 802.11 management frames, so record in monitor mode (for example with airodump-ng, tcpdump -I or Wireshark).",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Analyze capture: give the path of a .pcap / .pcapng file. Prints a summary (frames, peak rate, sources, victims, PMF status ...), a findings table and an A+..F grade. The result is kept for [05] and [06]."},
	{"02", "Run synthetic demo: analyzes a built-in fake flood so you can see every type of finding. No file needed."},
	{"03", "Reason code reference: table of IEEE 802.11 reason codes (e.g. 7 = class 3 frame from a non-associated station). Attack tools usually use a fixed code."},
	{"04", "Deauth frame lab: shows the bytes of a sample deauth frame field by field (hex dump) for learning. Use --reason N on the command line to choose the reason code. Nothing is sent."},
	{"05", "Show last report: prints the most recent analysis again."},
	{"06", "Export report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "A few deauths are normal (clients leaving). Dozens per second, broadcast deauths or bursts under 2 ms point to an attack tool."},
	{"*", "If the access point requires PMF (802.11w), forged deauths have no effect. ODeauth tells you whether PMF is on."},
	{"*", "--window N changes the flood-rate window and --wave-gap N the pause that splits attack waves (see next page)."},
	{"*", "Use only on networks you own or are allowed to test. The legal notes are on page 3."},
}

func owlHelpCLI() {
	printUsage()
	pause()
	renderHowto(hookHowto())
}
