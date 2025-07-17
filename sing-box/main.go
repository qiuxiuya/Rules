package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func fetch(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat"
	})
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat.sha256sum"
	})
	if geositeAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite checksum not found in upstream release ", release.Name)
	}
	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("checksum mismatch")
	}
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, entry := range vGeositeList.Entry {
		code := strings.ToLower(entry.CountryCode)
		var domains []geosite.Item
		attributes := map[string][]*routercommon.Domain{}
		for _, d := range entry.Domain {
			for _, attr := range d.Attribute {
				attributes[attr.Key] = append(attributes[attr.Key], d)
			}
			switch d.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainKeyword, Value: d.Value})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainRegex, Value: d.Value})
			case routercommon.Domain_RootDomain:
				if strings.Contains(d.Value, ".") {
					domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
				}
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainSuffix, Value: "." + d.Value})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attr, attrEntries := range attributes {
			var attrDomains []geosite.Item
			for _, d := range attrEntries {
				switch d.Type {
				case routercommon.Domain_Plain:
					attrDomains = append(attrDomains, geosite.Item{Type: geosite.RuleTypeDomainKeyword, Value: d.Value})
				case routercommon.Domain_Regex:
					attrDomains = append(attrDomains, geosite.Item{Type: geosite.RuleTypeDomainRegex, Value: d.Value})
				case routercommon.Domain_RootDomain:
					if strings.Contains(d.Value, ".") {
						attrDomains = append(attrDomains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
					}
					attrDomains = append(attrDomains, geosite.Item{Type: geosite.RuleTypeDomainSuffix, Value: "." + d.Value})
				case routercommon.Domain_Full:
					attrDomains = append(attrDomains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
				}
			}
			domainMap[code+"@"+attr] = common.Uniq(attrDomains)
		}
	}
	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) {
	var filteredCodeMap, mergedCodeMap []string
	var badCodeList []filteredCodePair
	for code := range data {
		if parts := strings.Split(code, "@"); len(parts) == 2 {
			last := strings.Split(parts[0], "-")
			base := last[len(last)-1]
			if base == "" {
				base = parts[0]
			}
			if base == parts[1] {
				delete(data, code)
				filteredCodeMap = append(filteredCodeMap, code)
			} else if "!"+base == parts[1] || base == "!"+parts[1] {
				badCodeList = append(badCodeList, filteredCodePair{code: parts[0], badCode: code})
			}
		}
	}
	for _, b := range badCodeList {
		badList := data[b.badCode]
		delete(data, b.badCode)
		unique := make(map[geosite.Item]bool)
		for _, i := range data[b.code] {
			unique[i] = true
		}
		for _, i := range badList {
			delete(unique, i)
		}
		newList := make([]geosite.Item, 0, len(unique))
		for item := range unique {
			newList = append(newList, item)
		}
		data[b.code] = newList
		mergedCodeMap = append(mergedCodeMap, b.badCode)
	}
	sort.Strings(filteredCodeMap)
	sort.Strings(mergedCodeMap)
	os.Stderr.WriteString("filtered " + strings.Join(filteredCodeMap, ",") + "\n")
	os.Stderr.WriteString("merged " + strings.Join(mergedCodeMap, ",") + "\n")
}

func mergeTags(data map[string][]geosite.Item) {
	var cnCodes []string
	for code := range data {
		if parts := strings.Split(code, "@"); len(parts) == 2 {
			if parts[1] == "cn" && strings.HasPrefix(parts[0], "category-") && !strings.HasSuffix(parts[0], "-cn") {
				cnCodes = append(cnCodes, code)
			}
		} else if strings.HasPrefix(code, "category-") && strings.HasSuffix(code, "-cn") {
			cnCodes = append(cnCodes, code)
		}
	}
	union := make(map[geosite.Item]bool)
	for _, item := range data["geolocation-cn"] {
		union[item] = true
	}
	for _, code := range cnCodes {
		for _, item := range data[code] {
			union[item] = true
		}
	}
	merged := make([]geosite.Item, 0, len(union))
	for item := range union {
		merged = append(merged, item)
	}
	data["geolocation-cn"] = merged
	data["cn"] = append(merged, geosite.Item{Type: geosite.RuleTypeDomainSuffix, Value: "cn"})
	println("merged cn categories: " + strings.Join(cnCodes, ","))
}

func generate(release *github.RepositoryRelease, ruleSetOutput string, ruleSetUnstableOutput string) error {
	vData, err := download(release)
	if err != nil {
		return err
	}
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	filterTags(domainMap)
	mergeTags(domainMap)

	os.RemoveAll(ruleSetOutput)
	os.RemoveAll(ruleSetUnstableOutput)
	os.MkdirAll(ruleSetOutput, 0o755)
	os.MkdirAll(ruleSetUnstableOutput, 0o755)

	for code, domains := range domainMap {
		defaultRule := geosite.Compile(domains)
		headlessRule := option.DefaultHeadlessRule{
			Domain:        defaultRule.Domain,
			DomainSuffix:  defaultRule.DomainSuffix,
			DomainKeyword: defaultRule.DomainKeyword,
			DomainRegex:   defaultRule.DomainRegex,
		}
		ruleSet := option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{Type: C.RuleTypeDefault, DefaultOptions: headlessRule},
			},
		}
		srsPath := filepath.Join(ruleSetOutput, code+".srs")
		unstablePath := filepath.Join(ruleSetUnstableOutput, code+".srs")

		f1, err := os.Create(srsPath)
		if err != nil {
			return err
		}
		if err := srs.Write(f1, ruleSet, false); err != nil {
			f1.Close()
			return err
		}
		f1.Close()

		f2, err := os.Create(unstablePath)
		if err != nil {
			return err
		}
		if err := srs.Write(f2, ruleSet, true); err != nil {
			f2.Close()
			return err
		}
		f2.Close()
	}
	return nil
}

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

func release(source, destination, ruleSetOutput, ruleSetUnstableOutput string) error {
	src, err := fetch(source)
	if err != nil {
		return err
	}
	dst, err := fetch(destination)
	if err != nil {
		log.Warn("missing destination latest release")
	} else if os.Getenv("NO_SKIP") != "true" && strings.Contains(*dst.Name, *src.Name) {
		log.Info("already latest")
		setActionOutput("skip", "true")
		return nil
	}
	err = generate(src, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}
	setActionOutput("tag", *src.Name)
	return nil
}

func main() {
	if err := release(
		"v2fly/domain-list-community",
		"sagernet/sing-geosite",
		"rule-set",
		"rule-set-unstable",
	); err != nil {
		log.Fatal(err)
	}
}
