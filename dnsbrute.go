package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	//"github.com/zedundun/dnsbrute/api"
	"github.com/zedundun/dnsbrute/dns"
	"github.com/zedundun/dnsbrute/log"
)

const versionNumber = "2.0.1#20180301"
const timeout = 5 * time.Second

func main() {
	version := flag.Bool("version", false, "Show program's version number and exit")
	domain := flag.String("domain", "", "Domain to brute")
	server := flag.String("server", "8.8.8.8:53", "Address of DNS server")
	dict := flag.String("dict", "dict/53683.txt", "Dict file")
	rate := flag.Int("rate", 10000, "Transmit rate of packets")
	retry := flag.Int("retry", 3, "Limit for retry")
	debug := flag.Bool("debug", false, "Show debug information")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [Options]\n\nOptions\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		fmt.Println(versionNumber)
		return
	}
	if *domain == "" {
		flag.Usage()
		return
	}
	if *debug {
		log.SetLevel(log.DEBUG)
	}

	start := time.Now()
	subDomainsToQuery := mixInAPIDict(*domain, *dict)
	dns.Configure(*domain, *server, *rate, *retry)

	// 输入
	go func() {
		for sub := range subDomainsToQuery {
			dns.Queries <- sub
		}
	}()

	// 输出
	file, err := os.Create(*domain + ".csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// csv
	csvOut := csv.NewWriter(file)
	defer csvOut.Flush()
	csvOut.Write([]string{"Domain", "Type", "CNAME", "IP"})

	counter := 0
	for record := range dns.Records {
		counter++
		out := record.CSV()
		log.Info(out)
		csvOut.Write(out)
	}

	log.Infof("done in %.2f seconds, %d records\n", time.Since(start).Seconds(), counter)
}

func mixInAPIDict(domain, dict string) <-chan string {
	subDomainsToQuery := make(chan string)
	mix := make(chan string)

	// mix in to subDomainsToQuery
	go func() {
		defer close(subDomainsToQuery)

		domains := map[string]struct{}{}
		for sub := range mix {
			domains[sub] = struct{}{}
		}

		for domain := range domains {
			subDomainsToQuery <- domain
		}
	}()

	go func() {
		defer close(mix)

		// Domain
		mix <- domain

		//call API to get subDomain
		//https://api.hackertarget.com/dnslookup/?q=domain
		url := "http://api.hackertarget.com/hostsearch/?q=" + domain
		client := http.Client{Timeout: timeout}
		resp, err := client.Get(url)
		if err != nil {
			log.Info("error while fetching api.hackertarget.com:", err)
		} else {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				record := scanner.Text()
				if record != "" {
					fmt.Println(strings.Split(record, ",")[0])
					mix <- strings.Split(record, ",")[0]
				}
			}
			resp.Body.Close()
		}

		// get subDomain for dict
		file, err := os.Open(dict)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			mix <- scanner.Text() + "." + domain
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}()

	return subDomainsToQuery
}
