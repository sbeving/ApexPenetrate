// internal/core/wordlist_manager.go
package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// WordlistType represents different types of wordlists
type WordlistType string

const (
	WordlistDirectories WordlistType = "directories"
	WordlistFiles       WordlistType = "files"
	WordlistSubdomains  WordlistType = "subdomains"
	WordlistParameters  WordlistType = "parameters"
	WordlistPasswords   WordlistType = "passwords"
	WordlistUsernames   WordlistType = "usernames"
	WordlistTechnology  WordlistType = "technology"
	WordlistAPIs        WordlistType = "apis"
	WordlistBackups     WordlistType = "backups"
	WordlistAdmin       WordlistType = "admin"
	WordlistCustom      WordlistType = "custom"
)

// WordlistSource represents the source of a wordlist
type WordlistSource string

const (
	SourceBuiltIn    WordlistSource = "builtin"
	SourceCommunity  WordlistSource = "community"
	SourceCustom     WordlistSource = "custom"
	SourceGenerated  WordlistSource = "generated"
	SourceDownloaded WordlistSource = "downloaded"
)

// Wordlist represents a collection of words/phrases
type Wordlist struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Type        WordlistType   `json:"type"`
	Source      WordlistSource `json:"source"`
	Words       []string       `json:"words"`
	Size        int            `json:"size"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Author      string         `json:"author"`
	Version     string         `json:"version"`
	URL         string         `json:"url,omitempty"`
	Tags        []string       `json:"tags"`
	Quality     float64        `json:"quality"` // 0-1 score based on effectiveness
}

// WordlistManager manages collections of wordlists
type WordlistManager struct {
	wordlists    map[string]*Wordlist
	wordlistDir  string
	defaultLists map[WordlistType]string
}

// NewWordlistManager creates a new wordlist manager
func NewWordlistManager(wordlistDir string) *WordlistManager {
	if wordlistDir == "" {
		wordlistDir = "./wordlists"
	}

	// Create directory if it doesn't exist
	os.MkdirAll(wordlistDir, 0755)

	wm := &WordlistManager{
		wordlists:   make(map[string]*Wordlist),
		wordlistDir: wordlistDir,
		defaultLists: map[WordlistType]string{
			WordlistDirectories: "common_directories",
			WordlistFiles:       "common_files",
			WordlistSubdomains:  "subdomain_prefixes",
			WordlistParameters:  "common_parameters",
			WordlistPasswords:   "common_passwords",
			WordlistUsernames:   "common_usernames",
		},
	}

	// Initialize with built-in wordlists
	wm.initializeBuiltInWordlists()
	wm.loadWordlistsFromDisk()

	return wm
}

// initializeBuiltInWordlists creates default wordlists
func (wm *WordlistManager) initializeBuiltInWordlists() {
	// Directory wordlist
	dirWordlist := &Wordlist{
		ID:          "common_directories",
		Name:        "Common Directories",
		Description: "Frequently found directories in web applications",
		Type:        WordlistDirectories,
		Source:      SourceBuiltIn,
		Words: []string{
			"admin", "administrator", "api", "assets", "backup", "backups", "bin", "blog", "cache",
			"cgi-bin", "config", "content", "css", "data", "db", "debug", "dev", "docs", "download",
			"downloads", "etc", "files", "forum", "ftp", "home", "html", "images", "img", "inc",
			"include", "includes", "index", "install", "js", "lib", "library", "log", "logs", "mail",
			"media", "modules", "new", "news", "old", "pages", "php", "pics", "private", "public",
			"resources", "scripts", "search", "secure", "shop", "site", "src", "static", "stats",
			"system", "temp", "template", "templates", "test", "tests", "tmp", "tools", "upload",
			"uploads", "user", "users", "var", "web", "webmail", "wp-admin", "wp-content", "wp-includes",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"web", "directory", "fuzzing"},
		Quality:   0.85,
	}
	dirWordlist.Size = len(dirWordlist.Words)

	// File wordlist
	fileWordlist := &Wordlist{
		ID:          "common_files",
		Name:        "Common Files",
		Description: "Common files and documents found on web servers",
		Type:        WordlistFiles,
		Source:      SourceBuiltIn,
		Words: []string{
			"robots.txt", "sitemap.xml", "favicon.ico", ".htaccess", ".htpasswd", "web.config",
			"index.html", "index.php", "index.asp", "index.jsp", "home.html", "default.html",
			"login.php", "admin.php", "config.php", "database.php", "db.php", "connect.php",
			"backup.sql", "dump.sql", "database.sql", "data.sql", "users.sql", "config.txt",
			"readme.txt", "README.md", "changelog.txt", "version.txt", "license.txt", "install.txt",
			"phpinfo.php", "info.php", "test.php", "debug.php", "error.log", "access.log",
			"admin.html", "administrator.html", "panel.html", "control.html", "manager.html",
			"password.txt", "passwords.txt", "users.txt", "accounts.txt", "credentials.txt",
			".env", ".env.local", ".env.production", ".git/config", ".svn/entries", ".DS_Store",
			"Thumbs.db", "desktop.ini", "composer.json", "package.json", "bower.json", "gulpfile.js",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"web", "file", "fuzzing"},
		Quality:   0.90,
	}
	fileWordlist.Size = len(fileWordlist.Words)

	// Subdomain wordlist
	subdomainWordlist := &Wordlist{
		ID:          "subdomain_prefixes",
		Name:        "Subdomain Prefixes",
		Description: "Common subdomain prefixes for enumeration",
		Type:        WordlistSubdomains,
		Source:      SourceBuiltIn,
		Words: []string{
			"www", "mail", "email", "webmail", "ftp", "admin", "administrator", "root", "test",
			"demo", "dev", "development", "staging", "stage", "qa", "uat", "prod", "production",
			"api", "app", "apps", "mobile", "m", "beta", "alpha", "preview", "blog", "news",
			"shop", "store", "portal", "secure", "ssl", "vpn", "remote", "access", "login",
			"panel", "control", "manage", "manager", "dashboard", "cpanel", "plesk", "whm",
			"ns", "ns1", "ns2", "dns", "mx", "pop", "imap", "smtp", "exchange", "autodiscover",
			"static", "assets", "cdn", "media", "images", "img", "css", "js", "files", "download",
			"git", "svn", "cvs", "repo", "repository", "code", "source", "backup", "old",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"subdomain", "dns", "enumeration"},
		Quality:   0.80,
	}
	subdomainWordlist.Size = len(subdomainWordlist.Words)

	// Parameter wordlist
	paramWordlist := &Wordlist{
		ID:          "common_parameters",
		Name:        "Common Parameters",
		Description: "Common HTTP parameters for testing",
		Type:        WordlistParameters,
		Source:      SourceBuiltIn,
		Words: []string{
			"id", "user", "username", "email", "password", "pass", "pwd", "token", "session",
			"auth", "login", "logout", "redirect", "url", "link", "page", "file", "path", "dir",
			"search", "q", "query", "keyword", "term", "name", "value", "data", "input", "output",
			"action", "method", "type", "format", "callback", "jsonp", "api_key", "key", "secret",
			"access_token", "refresh_token", "csrf_token", "nonce", "timestamp", "sig", "signature",
			"debug", "test", "admin", "mode", "env", "config", "settings", "option", "param",
			"var", "variable", "field", "column", "table", "database", "db", "sql", "cmd", "command",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"parameter", "fuzzing", "testing"},
		Quality:   0.85,
	}
	paramWordlist.Size = len(paramWordlist.Words)

	// Password wordlist
	passwordWordlist := &Wordlist{
		ID:          "common_passwords",
		Name:        "Common Passwords",
		Description: "Most commonly used passwords for brute force attacks",
		Type:        WordlistPasswords,
		Source:      SourceBuiltIn,
		Words: []string{
			"password", "123456", "password123", "admin", "letmein", "welcome", "monkey", "dragon",
			"qwerty", "abc123", "111111", "iloveyou", "adobe123", "123123", "sunshine", "1234567890",
			"princess", "azerty", "trustno1", "000000", "password1", "123456789", "12345678",
			"qwerty123", "1q2w3e4r", "admin123", "root", "toor", "pass", "test", "guest", "user",
			"demo", "default", "changeme", "secret", "backup", "temp", "administrator", "sa",
			"postgres", "mysql", "oracle", "master", "system", "login", "access", "security",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"password", "brute-force", "authentication"},
		Quality:   0.75,
	}
	passwordWordlist.Size = len(passwordWordlist.Words)

	// Username wordlist
	usernameWordlist := &Wordlist{
		ID:          "common_usernames",
		Name:        "Common Usernames",
		Description: "Common usernames for brute force attacks",
		Type:        WordlistUsernames,
		Source:      SourceBuiltIn,
		Words: []string{
			"admin", "administrator", "root", "user", "test", "guest", "demo", "operator", "manager",
			"service", "support", "help", "info", "mail", "email", "webmaster", "www", "ftp",
			"anonymous", "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "news",
			"uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "sshd", "mysql",
			"postgres", "oracle", "mssql", "apache", "nginx", "tomcat", "jenkins", "git", "svn",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "ApexPenetrate",
		Version:   "1.0",
		Tags:      []string{"username", "brute-force", "authentication"},
		Quality:   0.80,
	}
	usernameWordlist.Size = len(usernameWordlist.Words)

	// Store built-in wordlists
	wm.wordlists[dirWordlist.ID] = dirWordlist
	wm.wordlists[fileWordlist.ID] = fileWordlist
	wm.wordlists[subdomainWordlist.ID] = subdomainWordlist
	wm.wordlists[paramWordlist.ID] = paramWordlist
	wm.wordlists[passwordWordlist.ID] = passwordWordlist
	wm.wordlists[usernameWordlist.ID] = usernameWordlist

	// Save to disk
	wm.saveWordlistToDisk(dirWordlist)
	wm.saveWordlistToDisk(fileWordlist)
	wm.saveWordlistToDisk(subdomainWordlist)
	wm.saveWordlistToDisk(paramWordlist)
	wm.saveWordlistToDisk(passwordWordlist)
	wm.saveWordlistToDisk(usernameWordlist)
}

// GetWordlist returns a wordlist by ID
func (wm *WordlistManager) GetWordlist(id string) *Wordlist {
	return wm.wordlists[id]
}

// GetWordlistByType returns the default wordlist for a given type
func (wm *WordlistManager) GetWordlistByType(wordlistType WordlistType) *Wordlist {
	if defaultID, exists := wm.defaultLists[wordlistType]; exists {
		return wm.wordlists[defaultID]
	}
	return nil
}

// ListWordlists returns all available wordlists
func (wm *WordlistManager) ListWordlists() []*Wordlist {
	var wordlists []*Wordlist
	for _, wl := range wm.wordlists {
		wordlists = append(wordlists, wl)
	}
	
	// Sort by quality (descending) then by name
	sort.Slice(wordlists, func(i, j int) bool {
		if wordlists[i].Quality != wordlists[j].Quality {
			return wordlists[i].Quality > wordlists[j].Quality
		}
		return wordlists[i].Name < wordlists[j].Name
	})
	
	return wordlists
}

// CreateWordlist creates a new custom wordlist
func (wm *WordlistManager) CreateWordlist(name, description string, wordlistType WordlistType, words []string) *Wordlist {
	id := generateWordlistID(name)
	
	wordlist := &Wordlist{
		ID:          id,
		Name:        name,
		Description: description,
		Type:        wordlistType,
		Source:      SourceCustom,
		Words:       words,
		Size:        len(words),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Author:      "Custom",
		Version:     "1.0",
		Tags:        []string{"custom"},
		Quality:     0.5, // Default quality for custom lists
	}
	
	wm.wordlists[id] = wordlist
	wm.saveWordlistToDisk(wordlist)
	
	return wordlist
}

// LoadWordlistFromFile loads a wordlist from a text file
func (wm *WordlistManager) LoadWordlistFromFile(filePath, name, description string, wordlistType WordlistType) (*Wordlist, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return wm.CreateWordlist(name, description, wordlistType, words), nil
}

// GenerateWordlist creates a wordlist based on patterns and rules
func (wm *WordlistManager) GenerateWordlist(config WordlistGenerationConfig) *Wordlist {
	words := generateWords(config)
	
	id := generateWordlistID(config.Name)
	wordlist := &Wordlist{
		ID:          id,
		Name:        config.Name,
		Description: config.Description,
		Type:        config.Type,
		Source:      SourceGenerated,
		Words:       words,
		Size:        len(words),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Author:      "ApexPenetrate Generator",
		Version:     "1.0",
		Tags:        append(config.Tags, "generated"),
		Quality:     0.6,
	}
	
	wm.wordlists[id] = wordlist
	wm.saveWordlistToDisk(wordlist)
	
	return wordlist
}

// WordlistGenerationConfig defines how to generate wordlists
type WordlistGenerationConfig struct {
	Name         string
	Description  string
	Type         WordlistType
	BaseWords    []string
	Patterns     []string
	MinLength    int
	MaxLength    int
	IncludeYears bool
	IncludeNumbers bool
	Tags         []string
}

// generateWords creates words based on generation config
func generateWords(config WordlistGenerationConfig) []string {
	var words []string
	
	// Add base words
	words = append(words, config.BaseWords...)
	
	// Apply patterns
	for _, baseWord := range config.BaseWords {
		for _, pattern := range config.Patterns {
			generated := applyPattern(baseWord, pattern)
			if len(generated) >= config.MinLength && len(generated) <= config.MaxLength {
				words = append(words, generated)
			}
		}
	}
	
	// Add years if requested
	if config.IncludeYears {
		currentYear := time.Now().Year()
		for _, baseWord := range config.BaseWords {
			for year := currentYear - 10; year <= currentYear + 2; year++ {
				words = append(words, fmt.Sprintf("%s%d", baseWord, year))
				words = append(words, fmt.Sprintf("%d%s", year, baseWord))
			}
		}
	}
	
	// Add numbers if requested
	if config.IncludeNumbers {
		for _, baseWord := range config.BaseWords {
			for i := 0; i <= 999; i++ {
				if i < 10 {
					words = append(words, fmt.Sprintf("%s0%d", baseWord, i))
				} else if i < 100 {
					words = append(words, fmt.Sprintf("%s%d", baseWord, i))
				}
			}
		}
	}
	
	// Remove duplicates
	return removeDuplicates(words)
}

// applyPattern applies a transformation pattern to a word
func applyPattern(word, pattern string) string {
	switch pattern {
	case "uppercase":
		return strings.ToUpper(word)
	case "lowercase":
		return strings.ToLower(word)
	case "capitalize":
		return strings.Title(word)
	case "reverse":
		return reverse(word)
	case "leet":
		return leetSpeak(word)
	default:
		return word
	}
}

// CombineWordlists merges multiple wordlists into one
func (wm *WordlistManager) CombineWordlists(ids []string, name, description string) *Wordlist {
	var allWords []string
	var tags []string
	
	for _, id := range ids {
		if wordlist := wm.wordlists[id]; wordlist != nil {
			allWords = append(allWords, wordlist.Words...)
			tags = append(tags, wordlist.Tags...)
		}
	}
	
	// Remove duplicates
	allWords = removeDuplicates(allWords)
	tags = removeDuplicateStrings(tags)
	
	return wm.CreateWordlist(name, description, WordlistCustom, allWords)
}

// FilterWordlist creates a filtered version of a wordlist
func (wm *WordlistManager) FilterWordlist(id string, filters WordlistFilters) *Wordlist {
	original := wm.wordlists[id]
	if original == nil {
		return nil
	}
	
	var filteredWords []string
	for _, word := range original.Words {
		if matchesFilters(word, filters) {
			filteredWords = append(filteredWords, word)
		}
	}
	
	newName := fmt.Sprintf("%s (Filtered)", original.Name)
	return wm.CreateWordlist(newName, "Filtered version of "+original.Description, original.Type, filteredWords)
}

// WordlistFilters defines filtering criteria
type WordlistFilters struct {
	MinLength    int
	MaxLength    int
	Contains     string
	StartsWith   string
	EndsWith     string
	Regex        string
	ExcludeRegex string
}

// matchesFilters checks if a word matches the filter criteria
func matchesFilters(word string, filters WordlistFilters) bool {
	if filters.MinLength > 0 && len(word) < filters.MinLength {
		return false
	}
	if filters.MaxLength > 0 && len(word) > filters.MaxLength {
		return false
	}
	if filters.Contains != "" && !strings.Contains(word, filters.Contains) {
		return false
	}
	if filters.StartsWith != "" && !strings.HasPrefix(word, filters.StartsWith) {
		return false
	}
	if filters.EndsWith != "" && !strings.HasSuffix(word, filters.EndsWith) {
		return false
	}
	// Add regex matching here if needed
	return true
}

// GetWordlistStats returns statistics about all wordlists
func (wm *WordlistManager) GetWordlistStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	totalWordlists := len(wm.wordlists)
	totalWords := 0
	typeCount := make(map[WordlistType]int)
	sourceCount := make(map[WordlistSource]int)
	
	for _, wl := range wm.wordlists {
		totalWords += wl.Size
		typeCount[wl.Type]++
		sourceCount[wl.Source]++
	}
	
	stats["total_wordlists"] = totalWordlists
	stats["total_words"] = totalWords
	stats["types"] = typeCount
	stats["sources"] = sourceCount
	stats["average_size"] = totalWords / totalWordlists
	
	return stats
}

// saveWordlistToDisk saves a wordlist to disk as JSON
func (wm *WordlistManager) saveWordlistToDisk(wordlist *Wordlist) error {
	filename := filepath.Join(wm.wordlistDir, wordlist.ID+".json")
	
	data, err := json.MarshalIndent(wordlist, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

// loadWordlistsFromDisk loads all wordlists from disk
func (wm *WordlistManager) loadWordlistsFromDisk() {
	files, err := filepath.Glob(filepath.Join(wm.wordlistDir, "*.json"))
	if err != nil {
		return
	}
	
	for _, file := range files {
		var wordlist Wordlist
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		
		if err := json.Unmarshal(data, &wordlist); err != nil {
			continue
		}
		
		wm.wordlists[wordlist.ID] = &wordlist
	}
}

// Utility functions
func generateWordlistID(name string) string {
	// Simple ID generation - in production, use better method
	clean := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s_%d", clean, timestamp)
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func removeDuplicateStrings(slice []string) []string {
	return removeDuplicates(slice) // Same function for strings
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func leetSpeak(s string) string {
	leetMap := map[rune]rune{
		'a': '@', 'A': '@',
		'e': '3', 'E': '3',
		'i': '1', 'I': '1',
		'o': '0', 'O': '0',
		's': '$', 'S': '$',
		't': '7', 'T': '7',
		'l': '1', 'L': '1',
	}
	
	var result []rune
	for _, r := range s {
		if replacement, exists := leetMap[r]; exists {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}
	
	return string(result)
}

// RandomWordlist creates a random wordlist for testing
func (wm *WordlistManager) RandomWordlist(size int, wordlistType WordlistType) *Wordlist {
	baseWords := []string{
		"test", "demo", "sample", "example", "random", "generated", "auto", "temp",
		"data", "info", "content", "item", "element", "object", "value", "field",
	}
	
	var words []string
	for i := 0; i < size; i++ {
		base := baseWords[rand.Intn(len(baseWords))]
		suffix := rand.Intn(10000)
		words = append(words, fmt.Sprintf("%s%d", base, suffix))
	}
	
	name := fmt.Sprintf("Random %s Wordlist", wordlistType)
	description := fmt.Sprintf("Randomly generated wordlist with %d words", size)
	
	return wm.CreateWordlist(name, description, wordlistType, words)
}
