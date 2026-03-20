package dnsencoder

import (
	"errors"
	"fmt"
	"strings"
)

var WordList256 = []string{
	"able", "acid", "aged", "also", "area", "army", "away", "baby", "back", "ball", "band", "bank", "base", "bath", "bear", "beat",
	"bell", "belt", "best", "bird", "blue", "boat", "body", "bond", "bone", "book", "boom", "boot", "born", "boss", "bowl", "brad",
	"box", "boy", "bulk", "bull", "burn", "bush", "busy", "call", "calm", "camp", "card", "care", "case", "cash", "cast", "cell",
	"chat", "chef", "chip", "city", "club", "coal", "coat", "code", "cold", "cook", "cool", "copy", "core", "cost", "crew", "crop",
	"dark", "data", "date", "dawn", "days", "dead", "deal", "dean", "dear", "debt", "deep", "deer", "desk", "dial", "diet", "disk",
	"door", "draw", "drop", "dual", "dust", "duty", "each", "earn", "east", "easy", "edge", "else", "even", "ever", "evil", "exit",
	"face", "fact", "fade", "fail", "fair", "fall", "farm", "fast", "fate", "fear", "feed", "feel", "feet", "fell", "felt", "file",
	"fill", "film", "find", "fine", "fire", "firm", "fish", "five", "flag", "flat", "flow", "food", "foot", "ford", "form", "fort",
	"four", "free", "frog", "from", "fuel", "full", "fund", "gain", "game", "gate", "gear", "gift", "girl", "give", "glad", "goal",
	"goes", "gold", "golf", "good", "gray", "grew", "grid", "grow", "gulf", "hair", "half", "hall", "hand", "hang", "hard", "harm",
	"hate", "have", "head", "hear", "heat", "held", "help", "here", "hero", "high", "hill", "hint", "hold", "hole", "holy", "home",
	"hope", "horn", "host", "hour", "huge", "hung", "hunt", "hurt", "idea", "inch", "into", "iron", "item", "jack", "jane", "jean",
	"john", "join", "jump", "jury", "just", "keen", "keep", "kent", "kept", "kick", "kill", "kind", "king", "knee", "knew", "know",
	"lack", "lady", "laid", "lake", "land", "lane", "last", "late", "lead", "leaf", "lean", "left", "less", "life", "lift", "like",
	"line", "link", "list", "live", "load", "loan", "lock", "logo", "long", "look", "lord", "lose", "loss", "lost", "love", "luck",
	"made", "mail", "main", "make", "male", "many", "mark", "mass", "mate", "math", "meal", "mean", "meat", "meet", "mere", "milk",
}

// DictionaryEncoder handles encoding data into low-entropy English word chains
type DictionaryEncoder struct {
	domain  string
	wordMap map[string]byte
}

// NewDictionaryEncoder creates a new dictionary DNS encoder
func NewDictionaryEncoder(domain string) *DictionaryEncoder {
	wm := make(map[string]byte)
	for i, w := range WordList256 {
		wm[w] = byte(i)
	}
	return &DictionaryEncoder{
		domain:  domain,
		wordMap: wm,
	}
}

// EncodeToSubdomains encodes data into DNS-safe English-word subdomains
func (e *DictionaryEncoder) EncodeToSubdomains(data []byte) ([]string, error) {
	var queries []string
	
	// Max bytes per query to keep the overall domain length safe
	// A single word is ~4 chars + 1 hyphen = 5 chars. 
	// 10 words = 50 chars (safe for a single DNS label of 63)
	// Let's divide into labels of 8 words. So 8 bytes per label.
	// E.g. word1-word2...-word8.domain.com
	
	chunkSize := 8 
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		var words []string
		
		// Encode Sequence number into the first 2 bytes? 
		// Actually, sequence number as hex like in standard encoder is okay,
		// but to keep entropy low, let's encode sequence as 2 words!
		seqWord1 := WordList256[(i/chunkSize) >> 8]
		seqWord2 := WordList256[(i/chunkSize) & 0xff]
		words = append(words, seqWord1, seqWord2)

		for _, b := range chunk {
			words = append(words, WordList256[b])
		}

		subdomain := strings.Join(words, "-")
		query := fmt.Sprintf("%s.%s", subdomain, e.domain)

		if len(query) > MaxDomainLength {
			return nil, fmt.Errorf("query exceeds maximum DNS name length: %d", len(query))
		}

		queries = append(queries, query)
	}

	return queries, nil
}

// DecodeFromSubdomain extracts data from an English-word DNS query
func (e *DictionaryEncoder) DecodeFromSubdomain(query string) ([]byte, int, error) {
	query = strings.TrimSuffix(query, "."+e.domain)
	query = strings.TrimSuffix(query, ".")

	parts := strings.Split(query, ".")
	// taking the first label which contains our words separated by hyphens (or multiple labels)
	// actually the words are joined by hyphens in a single label
	
	var allWords []string
	for _, part := range parts {
		words := strings.Split(part, "-")
		allWords = append(allWords, words...)
	}

	if len(allWords) < 2 {
		return nil, 0, errors.New("invalid query format, sequence missing")
	}

	seqBytes := make([]byte, 2)
	for i := 0; i < 2; i++ {
		b, ok := e.wordMap[allWords[i]]
		if !ok {
			return nil, 0, fmt.Errorf("invalid sequence dictionary word: %s", allWords[i])
		}
		seqBytes[i] = b
	}
	seqNum := (int(seqBytes[0]) << 8) | int(seqBytes[1])

	var data []byte
	for i := 2; i < len(allWords); i++ {
		b, ok := e.wordMap[allWords[i]]
		if !ok {
			return nil, 0, fmt.Errorf("invalid payload dictionary word: %s", allWords[i])
		}
		data = append(data, b)
	}

	return data, seqNum, nil
}
