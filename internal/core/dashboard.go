package core

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/table"
)

type DashboardStats struct {
	ModulesRunning   int
	ModulesCompleted int
	OpenPorts        int
	VulnsFound       int
	StartTime        time.Time
	Mutex            sync.Mutex
}

var dashboardStats = &DashboardStats{StartTime: time.Now()}

func UpdateDashboard(modulesRunning, modulesCompleted, openPorts, vulnsFound int) {
	dashboardStats.Mutex.Lock()
	dashboardStats.ModulesRunning = modulesRunning
	dashboardStats.ModulesCompleted = modulesCompleted
	dashboardStats.OpenPorts = openPorts
	dashboardStats.VulnsFound = vulnsFound
	dashboardStats.Mutex.Unlock()
}

func StartLiveDashboard(stopChan <-chan struct{}) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " Running scans..."
	s.Start()
	defer s.Stop()

	for {
		select {
		case <-stopChan:
			s.Stop()
			return
		default:
			dashboardStats.Mutex.Lock()
			t := table.NewWriter()
			t.SetOutputMirror(os.Stdout)
			t.SetStyle(table.StyleColoredBright)
			t.AppendHeader(table.Row{"Module Status", "Open Ports", "Vulns Found", "Elapsed"})
			t.AppendRow(table.Row{
				formatModuleStatus(dashboardStats.ModulesRunning, dashboardStats.ModulesCompleted),
				dashboardStats.OpenPorts,
				dashboardStats.VulnsFound,
				time.Since(dashboardStats.StartTime).Truncate(time.Second),
			})
			t.Render()
			dashboardStats.Mutex.Unlock()
			time.Sleep(1 * time.Second)
		}
	}
}

func formatModuleStatus(running, completed int) string {
	return fmt.Sprintf("▶ %d | ✔ %d", running, completed)
}
