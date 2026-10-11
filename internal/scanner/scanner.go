package scanner

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xytherion/core/pkg/metrics"
)

type portDef struct {
	service string
	risk    metrics.RiskLevel
	note    string
}

// knownPorts maps port → metadata. Only open ports are reported.
var knownPorts = map[int]portDef{
	21:    {"FTP", metrics.RiskHigh, "Transfert non chiffré, préférez SFTP"},
	22:    {"SSH", metrics.RiskInfo, "Accès shell sécurisé"},
	23:    {"Telnet", metrics.RiskCritical, "Protocole obsolète — aucun chiffrement"},
	25:    {"SMTP", metrics.RiskMedium, "Serveur mail — vérifiez les relais ouverts"},
	53:    {"DNS", metrics.RiskMedium, "Résolveur DNS exposé"},
	80:    {"HTTP", metrics.RiskLow, "Trafic web non chiffré"},
	110:   {"POP3", metrics.RiskMedium, "Protocole mail non chiffré"},
	135:   {"RPC", metrics.RiskHigh, "Windows RPC — vecteur d'exploitation fréquent"},
	139:   {"NetBIOS", metrics.RiskHigh, "Partage réseau Windows obsolète"},
	143:   {"IMAP", metrics.RiskMedium, "Protocole mail non chiffré"},
	443:   {"HTTPS", metrics.RiskInfo, "Trafic web sécurisé (TLS)"},
	445:   {"SMB", metrics.RiskCritical, "Cible principale des ransomwares (WannaCry, etc.)"},
	1433:  {"MSSQL", metrics.RiskHigh, "Base de données Microsoft SQL exposée"},
	1521:  {"Oracle DB", metrics.RiskHigh, "Base de données Oracle exposée"},
	2375:  {"Docker API", metrics.RiskCritical, "API Docker non chiffrée — accès root complet"},
	2376:  {"Docker TLS", metrics.RiskMedium, "API Docker sécurisée"},
	3000:  {"Dev HTTP", metrics.RiskLow, "Serveur de développement"},
	3306:  {"MySQL", metrics.RiskHigh, "Base de données exposée sur le réseau"},
	3389:  {"RDP", metrics.RiskCritical, "Bureau à distance Windows — cible d'attaques brute-force"},
	4444:  {"Metasploit", metrics.RiskCritical, "Port de bind shell / Metasploit par défaut"},
	5432:  {"PostgreSQL", metrics.RiskHigh, "Base de données exposée sur le réseau"},
	5900:  {"VNC", metrics.RiskHigh, "Bureau à distance — souvent sans chiffrement"},
	6379:  {"Redis", metrics.RiskCritical, "Redis sans authentification par défaut"},
	8080:  {"HTTP Alt", metrics.RiskLow, "Port HTTP alternatif"},
	8443:  {"HTTPS Alt", metrics.RiskLow, "Port HTTPS alternatif"},
	8888:  {"Jupyter", metrics.RiskHigh, "Notebook Jupyter — exécution de code à distance"},
	9200:  {"Elasticsearch", metrics.RiskCritical, "Elasticsearch sans authentification par défaut"},
	9300:  {"Elasticsearch", metrics.RiskHigh, "Nœud Elasticsearch exposé"},
	27017: {"MongoDB", metrics.RiskCritical, "MongoDB sans authentification par défaut"},
	27018: {"MongoDB Shard", metrics.RiskHigh, "MongoDB shard node exposé"},
}

func Scan(host string) metrics.ScanResult {
	start := time.Now()

	type work struct {
		port int
		def  portDef
	}

	jobs := make([]work, 0, len(knownPorts))
	for p, d := range knownPorts {
		jobs = append(jobs, work{p, d})
	}

	var (
		mu      sync.Mutex
		results []metrics.PortResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 80)
	)

	for _, j := range jobs {
		wg.Add(1)
		go func(j work) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, strconv.Itoa(j.port))
			conn, err := net.DialTimeout("tcp", addr, 600*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, metrics.PortResult{
					Port:    j.port,
					Service: j.def.service,
					Risk:    j.def.risk,
					Open:    true,
					Note:    j.def.note,
				})
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()

	// Sort: critical first, then by port number within same risk.
	order := map[metrics.RiskLevel]int{
		metrics.RiskCritical: 0,
		metrics.RiskHigh:     1,
		metrics.RiskMedium:   2,
		metrics.RiskLow:      3,
		metrics.RiskInfo:     4,
	}
	sort.Slice(results, func(i, j int) bool {
		ri, rj := order[results[i].Risk], order[results[j].Risk]
		if ri != rj {
			return ri < rj
		}
		return results[i].Port < results[j].Port
	})

	return metrics.ScanResult{
		Ports:      results,
		ScannedAt:  time.Now(),
		DurationMS: time.Since(start).Milliseconds(),
	}
}
