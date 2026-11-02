package filter

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
)

// labelsOf returns the registrable labels of names that DGAScore scores.
func labelsOf(names []string) []string {
	var labels []string
	for _, name := range names {
		reg := Registrable(name)
		if reg == "" {
			continue
		}
		label, _, _ := strings.Cut(reg, ".")
		if _, _, ok := DGAScore(label); ok {
			labels = append(labels, label)
		}
	}
	return labels
}

// dgaTraining returns the scored labels of the model's training corpus.
func dgaTraining(tb testing.TB) []string {
	tb.Helper()
	data, err := os.ReadFile("testdata/dga-train.txt")
	if err != nil {
		tb.Fatal(err)
	}
	var names []string
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			names = append(names, line)
		}
	}
	return labelsOf(names)
}

// flaggedRate returns the fraction of labels scoring over threshold, and
// those labels.
func flaggedRate(labels []string, threshold float64) (float64, []string) {
	var flagged []string
	for _, l := range labels {
		if s, _, ok := DGAScore(l); ok && s > threshold {
			flagged = append(flagged, l)
		}
	}
	return float64(len(flagged)) / float64(max(len(labels), 1)), flagged
}

// TestDGA_Threshold logs the training corpus's score percentiles, and
// checks that the default threshold flags at most 0.5% of it. Popular
// domains include some machine-generated names of their own, such as CDN
// shards and trackers' (cdnhwc…, ffbbbdc6…), so the corpus can't be
// flagged at zero.
func TestDGA_Threshold(t *testing.T) {
	labels := dgaTraining(t)
	scores := make([]float64, 0, len(labels))
	for _, l := range labels {
		s, _, _ := DGAScore(l)
		scores = append(scores, s)
	}
	slices.Sort(scores)
	for _, p := range []float64{0.5, 0.9, 0.99, 0.995, 0.999} {
		t.Logf("training p%.1f: %.2f", 100*p, scores[int(p*float64(len(scores)-1))])
	}

	rate, flagged := flaggedRate(labels, DefaultDGAThreshold)
	t.Logf("training: %d of %d labels (%.3f%%) over %.1f: %v", len(flagged), len(labels), 100*rate, DefaultDGAThreshold, flagged)
	if rate > 0.005 {
		t.Errorf("default threshold flags %.3f%% of the training corpus, over 0.5%%", 100*rate)
	}
}

// TestDGA_PopularDomains checks the held-out popular domains, which the
// model wasn't trained on. Set DOH_TRANCO to a Tranco list to report on
// more.
func TestDGA_PopularDomains(t *testing.T) {
	labels := labelsOf(topDomains(t))
	rate, flagged := flaggedRate(labels, DefaultDGAThreshold)
	t.Logf("held-out top domains: %d of %d scored labels (%.3f%%) flagged: %v", len(flagged), len(labels), 100*rate, flagged)
	if rate > 0.002 {
		t.Errorf("default threshold flags %.3f%% of popular domains, over 0.2%%", 100*rate)
	}

	if path := os.Getenv("DOH_TRANCO"); path != "" {
		all := tranco(t, path)
		if len(all) > 40_000 {
			all = all[40_000:] // past the training corpus
		}
		labels := labelsOf(all)
		rate, flagged := flaggedRate(labels, DefaultDGAThreshold)
		t.Logf("Tranco past rank 40,000: %d of %d scored labels (%.4f%%) flagged; first: %v", len(flagged), len(labels), 100*rate, flagged[:min(len(flagged), 60)])
	}
}

// TestDGA_Families measures recall on each family, requiring each
// family's minimum, and reports precision against the held-out popular
// domains.
func TestDGA_Families(t *testing.T) {
	popular := labelsOf(topDomains(t))
	_, fp := flaggedRate(popular, DefaultDGAThreshold)

	totalTP, total := 0, 0
	for _, fam := range dgaFamilies {
		names := fam.generate(1000)
		scored, flagged := 0, 0
		for _, l := range names {
			s, _, ok := DGAScore(l)
			if !ok {
				continue
			}
			scored++
			if s > DefaultDGAThreshold {
				flagged++
			}
		}
		recall := float64(flagged) / float64(max(scored, 1))
		t.Logf("%-24s recall %5.1f%% of all %d, %5.1f%% of the %d long enough to score",
			fam.name, 100*float64(flagged)/float64(len(names)), len(names), 100*recall, scored)
		if recall < fam.minRecall {
			t.Errorf("%s: recall %.1f%%, under %.0f%%", fam.name, 100*recall, 100*fam.minRecall)
		}
		totalTP += flagged
		total += len(names)
	}

	// Precision if as many popular names were queried as generated ones.
	falsePos := float64(len(fp)) / float64(len(popular)) * float64(total)
	t.Logf("all families: %d of %d names flagged (recall %.1f%%); precision against as many popular names: %.4f",
		totalTP, total, 100*float64(totalTP)/float64(total), float64(totalTP)/(float64(totalTP)+falsePos))
}

// TestDGA_Curve logs, for a range of thresholds, the share of training
// and held-out popular labels flagged, and each family's recall, to
// choose DefaultDGAThreshold by.
func TestDGA_Curve(t *testing.T) {
	training, popular := dgaTraining(t), labelsOf(topDomains(t))
	median := func(labels []string) float64 {
		var s []float64
		for _, l := range labels {
			if _, f, ok := DGAScore(l); ok {
				s = append(s, f.Surprise)
			}
		}
		slices.Sort(s)
		return s[len(s)/2]
	}
	line := fmt.Sprintf("median surprise: training %.2f, popular %.2f;", median(training), median(popular))
	for _, fam := range dgaFamilies {
		line += fmt.Sprintf(" %s %.2f", strings.Fields(fam.name)[0], median(fam.generate(1000)))
	}
	t.Log(line)

	for _, th := range []float64{8, 10, 12, 14, 16, 18, 20, 25} {
		trainRate, _ := flaggedRate(training, th)
		popRate, _ := flaggedRate(popular, th)
		line := fmt.Sprintf("threshold %.1f: training %.3f%%, popular %.3f%%;", th, 100*trainRate, 100*popRate)
		for _, fam := range dgaFamilies {
			rate, _ := flaggedRate(fam.generate(1000), th)
			line += fmt.Sprintf(" %s %.0f%%", strings.Fields(fam.name)[0], 100*rate)
		}
		t.Log(line)
	}
}

func TestDGAScore_Legitimate(t *testing.T) {
	for _, label := range []string{
		"wikipedia", "stackoverflow", "googleapis", "cloudflare", "microsoftonline", "doubleclick",
		"thisisaverylonglegitimatedomainnamethatgoesonandon", "internationalbusinessmachines",
		"bundesregierung", "xiaohongshu", "zhongguancun", "aliexpress", "googlesyndication",
		"llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch", "szczecin",
		"my-company-name", "1800flowers", "20minutes", "365scores", "bet365", "movies4u", "awsdns-21",
		"cdninstagram", "googleusercontent", "msftncsi", "akamaiedge", "pinduoduo", "kommersant",
	} {
		if s, f, ok := DGAScore(label); ok && s > DefaultDGAThreshold {
			t.Errorf("DGAScore(%q) = %.2f %+v; want it under %.1f", label, s, f, DefaultDGAThreshold)
		}
	}

	// Known false positives: long words in languages whose letter pairs
	// the model, trained mostly on English-like names, rarely saw. They're
	// why the protection is off by default; allow such domains if needed.
	for _, label := range []string{"szczecin-bydgoszcz", "chrzaszczyrzewoszyce"} {
		if s, _, ok := DGAScore(label); !ok || s <= DefaultDGAThreshold {
			t.Logf("known false positive %q now scores %.2f, under the threshold", label, s)
		}
	}

	// Labels that aren't scored.
	for _, label := range []string{"", "short", "xn--mnchen-3ya", "under_score", "UPPERCASE", strings.Repeat("q", 64)} {
		if _, _, ok := DGAScore(label); ok {
			t.Errorf("DGAScore(%q) scored it", label)
		}
	}
}

func TestDGAScore_Generated(t *testing.T) {
	for _, label := range []string{
		"xjwqkzrtvbnmplk", "qzkxjvwpbr", "4f8a9c2e7b1d", "d41d8cd98f00b204e9800998ecf8427e", "kq7zx2m9vt3w",
	} {
		if s, f, ok := DGAScore(label); !ok || s <= DefaultDGAThreshold {
			t.Errorf("DGAScore(%q) = %.2f %+v, %v; want it over %.1f", label, s, f, ok, DefaultDGAThreshold)
		}
	}
}

func TestDGA_Reason(t *testing.T) {
	why, ok := dga("xjwqkzrtvbnmplk.com", DefaultDGAThreshold)
	if !ok || !strings.HasPrefix(why, "xjwqkzrtvbnmplk.com looks machine-generated (score ") {
		t.Errorf("dga = %q, %v", why, ok)
	}
	if why, ok := dga("wikipedia.org", DefaultDGAThreshold); ok {
		t.Errorf("dga(wikipedia.org) = %q", why)
	}
	// A higher threshold flags less.
	if _, ok := dga("xjwqkzrtvbnmplk.com", 100); ok {
		t.Error("dga flagged a label under its threshold")
	}
}

func TestDGAModel(t *testing.T) {
	// Each row is a probability distribution over what follows.
	for prev := range dgaSymbols - 1 {
		var sum float64
		for next := range dgaSymbols {
			sum += math.Exp2(float64(dgaBigram[prev*dgaSymbols+next]))
		}
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("row %d sums to %.4f", prev, sum)
		}
	}
	// Common English bigrams are likelier than rare ones.
	p := func(a, b byte) float32 { return dgaBigram[dgaSymbol(a)*dgaSymbols+dgaSymbol(b)] }
	if p('t', 'h') <= p('q', 'z') || p('i', 'n') <= p('x', 'j') {
		t.Error("the model doesn't look like English")
	}
}

func FuzzDGAScore(f *testing.F) {
	for _, s := range []string{"example", "xjwqkzrtvbnmplk", "a-b-c-d-e-f", "0123456789", "xn--abc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, label string) {
		s, feat, ok := DGAScore(label)
		if !ok {
			return
		}
		if feat.Length != len(label) || feat.Surprise < 0 || feat.Entropy < 0 || feat.Digits < 0 || feat.Digits > 1 || feat.ConsonantRun > len(label) {
			t.Fatalf("DGAScore(%q) features %+v", label, feat)
		}
		if math.IsNaN(s) || math.IsInf(s, 0) {
			t.Fatalf("DGAScore(%q) = %v", label, s)
		}
	})
}

func BenchmarkDGAScore(b *testing.B) {
	for _, label := range []string{"wikipedia", "xjwqkzrtvbnmplk", "thisisaverylonglegitimatedomainname"} {
		b.Run(label, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				DGAScore(label)
			}
		})
	}
}
