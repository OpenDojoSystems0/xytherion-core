package procdna

import (
	"fmt"

	"github.com/xytherion/core/pkg/metrics"
)

// Violation représente un dépassement de seuil pour un processus connu.
type Violation struct {
	Process string `json:"process"`
	PID     int32  `json:"pid"`
	Rule    string `json:"rule"`
	Detail  string `json:"detail"`
}

type profile struct {
	maxCPU float64
	maxMem float32
}

// profiles contient les seuils max pour les processus connus.
var profiles = map[string]profile{
	"nginx":        {maxCPU: 30.0, maxMem: 5.0},
	"apache2":      {maxCPU: 50.0, maxMem: 10.0},
	"httpd":        {maxCPU: 50.0, maxMem: 10.0},
	"postgres":     {maxCPU: 70.0, maxMem: 25.0},
	"mysqld":       {maxCPU: 70.0, maxMem: 30.0},
	"redis-server": {maxCPU: 20.0, maxMem: 10.0},
	"mongod":       {maxCPU: 60.0, maxMem: 30.0},
	"sshd":         {maxCPU: 5.0, maxMem: 1.0},
	"node":         {maxCPU: 80.0, maxMem: 20.0},
	"python3":      {maxCPU: 80.0, maxMem: 20.0},
	"java":         {maxCPU: 90.0, maxMem: 50.0},
	"dockerd":      {maxCPU: 40.0, maxMem: 10.0},
	"containerd":   {maxCPU: 30.0, maxMem: 5.0},
	"caddy":        {maxCPU: 30.0, maxMem: 5.0},
	"prometheus":   {maxCPU: 40.0, maxMem: 15.0},
}

// Check analyse les processus et retourne les violations détectées.
// Les processus non reconnus sont ignorés.
func Check(procs []metrics.Process) []Violation {
	var violations []Violation
	for _, p := range procs {
		prof, known := profiles[p.Name]
		if !known {
			continue
		}
		if p.CPU > prof.maxCPU {
			violations = append(violations, Violation{
				Process: p.Name,
				PID:     p.PID,
				Rule:    "cpu_exceeded",
				Detail: fmt.Sprintf(
					"%s (pid %d) uses %.1f%% CPU, limit is %.1f%%",
					p.Name, p.PID, p.CPU, prof.maxCPU,
				),
			})
		}
		if p.Memory > prof.maxMem {
			violations = append(violations, Violation{
				Process: p.Name,
				PID:     p.PID,
				Rule:    "mem_exceeded",
				Detail: fmt.Sprintf(
					"%s (pid %d) uses %.1f%% MEM, limit is %.1f%%",
					p.Name, p.PID, p.Memory, prof.maxMem,
				),
			})
		}
	}
	return violations
}
