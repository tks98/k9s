package view

import (
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/ui"
	"github.com/gdamore/tcell/v2"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"time"
)

type AquaSecurityKubeBenchReports struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Report     Report   `yaml:"report"`
}
type Labels struct {
	StarboardResourceKind string `yaml:"starboard.resource.kind"`
	StarboardResourceName string `yaml:"starboard.resource.name"`
}
type OwnerReferences struct {
	APIVersion         string `yaml:"apiVersion"`
	BlockOwnerDeletion bool   `yaml:"blockOwnerDeletion"`
	Controller         bool   `yaml:"controller"`
	Kind               string `yaml:"kind"`
	Name               string `yaml:"name"`
	UID                string `yaml:"uid"`
}
type Metadata struct {
	CreationTimestamp time.Time         `yaml:"creationTimestamp"`
	Generation        int               `yaml:"generation"`
	Labels            Labels            `yaml:"labels"`
	Name              string            `yaml:"name"`
	OwnerReferences   []OwnerReferences `yaml:"ownerReferences"`
	ResourceVersion   string            `yaml:"resourceVersion"`
	UID               string            `yaml:"uid"`
}
type Scanner struct {
	Name    string `yaml:"name"`
	Vendor  string `yaml:"vendor"`
	Version string `yaml:"version"`
}
type Results struct {
	Remediation string `yaml:"remediation"`
	Scored      bool   `yaml:"scored"`
	Status      string `yaml:"status"`
	TestDesc    string `yaml:"test_desc"`
	TestNumber  string `yaml:"test_number"`
}
type Tests struct {
	Desc    string    `yaml:"desc"`
	Fail    int       `yaml:"fail"`
	Info    int       `yaml:"info"`
	Pass    int       `yaml:"pass"`
	Results []Results `yaml:"results"`
	Section string    `yaml:"section"`
	Warn    int       `yaml:"warn"`
}
type Sections struct {
	ID        string  `yaml:"id"`
	NodeType  string  `yaml:"node_type"`
	Tests     []Tests `yaml:"tests"`
	Text      string  `yaml:"text"`
	TotalFail int     `yaml:"total_fail"`
	TotalInfo int     `yaml:"total_info"`
	TotalPass int     `yaml:"total_pass"`
	TotalWarn int     `yaml:"total_warn"`
	Version   string  `yaml:"version"`
}
type Summary struct {
	FailCount int `yaml:"failCount"`
	InfoCount int `yaml:"infoCount"`
	PassCount int `yaml:"passCount"`
	WarnCount int `yaml:"warnCount"`
}
type Report struct {
	Scanner         Scanner    `yaml:"scanner"`
	Sections        []Sections `yaml:"sections"`
	Summary         Summary    `yaml:"summary"`
	UpdateTimestamp time.Time  `yaml:"updateTimestamp"`
}

// CISKubeBenchReport presents a CISKubeBenchReport viewer.
type CISKubeBenchReport struct {
	ResourceViewer
}

// NewCISKubeBenchReport returns a new viewer.
func NewCISKubeBenchReport(gvr client.GVR) ResourceViewer {
	vr  := CISKubeBenchReport{
		ResourceViewer: NewBrowser(gvr),
	}
	vr.AddBindKeysFn(vr .bindKeys)

	return &vr
}

func (vr *CISKubeBenchReport) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyX: ui.NewKeyAction("ViewReportSummary", vr.viewReport, true),
	})
}

func (vr *CISKubeBenchReport) refCmd(evt *tcell.EventKey) *tcell.EventKey {
	return scanRefs(evt, vr.App(), vr.GetTable(), "aquasecurity.github.io/v1alpha1/ciskubebenchreports")
}

func (vr *CISKubeBenchReport) viewReport(evt *tcell.EventKey) *tcell.EventKey {
	path := vr.GetTable().GetSelectedItem()
	if path == "" {
		return evt
	}

	r, err := vr.App().factory.Get(vr .GVR().String(), path, true, labels.Everything())
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	/*
	For some reason, utilizing this method of unmarshalling the unstructured data causes data loss
	The method performed after this comment allows for all required data to unmarshal correctly into the AquaSecurityKubeBenchReport type

	var report AquaSecurityKubeBenchReports
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(r.(*unstructured.Unstructured).Object, &report)
	if err != nil {
		vr .App().Flash().Err(err)
		return nil
	}*/


	reportMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(r)
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	var report AquaSecurityKubeBenchReports
	b, err := yaml.Marshal(reportMap)
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	err = yaml.Unmarshal(b, &report)
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	type testSummary struct {
		TestNumber string
		Description string
		Status string
	}

	kbrs := make(map[string][]testSummary)
	for _, section := range report.Report.Sections {
		for _, test := range section.Tests {
			for _, result := range test.Results {
				var ts testSummary
				ts.Status = result.Status
				ts.Description = result.TestDesc
				ts.TestNumber = result.TestNumber
				kbrs[test.Desc] = append(kbrs[test.Desc], ts)
			}
		}
	}

	raw, err := yaml.Marshal(kbrs)
	if err != nil {
		vr .App().Flash().Errf("Error decoding kubebenchreport %vr ", err)
		return nil
	}

	details := NewDetails(vr .App(), "KubeBench Report Summary", path, true).Update(string(raw))
	if err := vr .App().inject(details); err != nil {
		vr .App().Flash().Err(err)
	}

	return nil
}
