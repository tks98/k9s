package view

import (
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/ui"
	"github.com/gdamore/tcell/v2"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// AquaSecurityKubeHunterReport represents an aqua kube-hunter report crd
type AquaSecurityKubeHunterReport struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name   string `yaml:"name"`
		Labels struct {
			StarboardResourceKind string `yaml:"starboard.resource.kind"`
			StarboardResourceName string `yaml:"starboard.resource.name"`
		} `yaml:"labels"`
		UID string `yaml:"uid"`
	} `yaml:"metadata"`
	Report struct {
		Scanner struct {
			Name    string `yaml:"name"`
			Vendor  string `yaml:"vendor"`
			Version string `yaml:"version"`
		} `yaml:"scanner"`
		Summary struct {
			HighCount    int `yaml:"highCount"`
			LowCount     int `yaml:"lowCount"`
			MediumCount  int `yaml:"mediumCount"`
			UnknownCount int `yaml:"unknownCount"`
		} `yaml:"summary"`
		Vulnerabilities []struct {
			AvdReference  string `yaml:"avd_reference"`
			Category      string `yaml:"category"`
			Description   string `yaml:"description"`
			Evidence      string `yaml:"evidence"`
			Location      string `yaml:"location"`
			Severity      string `yaml:"severity"`
			Vid           string `yaml:"vid"`
			Vulnerability string `yaml:"vulnerability"`
		} `yaml:"vulnerabilities"`
	} `yaml:"report"`
}

// KubeHunterReport presents a KubeHunterReport viewer.
type KubeHunterReport struct {
	ResourceViewer
}

// NewKubeHunterReport returns a new viewer.
func NewKubeHunterReport(gvr client.GVR) ResourceViewer {
	vr := KubeHunterReport{
		ResourceViewer: NewBrowser(gvr),
	}
	vr.AddBindKeysFn(vr.bindKeys)

	return &vr
}

func (vr *KubeHunterReport) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyX: ui.NewKeyAction("View Report Summary", vr.viewReport, true),
	})
}

func (vr *KubeHunterReport) refCmd(evt *tcell.EventKey) *tcell.EventKey {
	return scanRefs(evt, vr.App(), vr.GetTable(), "aquasecurity.github.io/v1alpha1/ciskubebenchreports")
}

func (vr *KubeHunterReport) viewReport(evt *tcell.EventKey) *tcell.EventKey {
	path := vr.GetTable().GetSelectedItem()
	if path == "" {
		return evt
	}

	r, err := vr.App().factory.Get(vr.GVR().String(), path, true, labels.Everything())
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	var report AquaSecurityKubeHunterReport
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(r.(*unstructured.Unstructured).Object, &report)
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	type reportSummary struct {
		Severity    string
		Description string
		Category    string
	}

	summary := make(map[string]reportSummary, len(report.Report.Vulnerabilities))
	for _, val := range report.Report.Vulnerabilities {
		summary[val.Vulnerability] = reportSummary {
			Severity:    val.Severity,
			Description: val.Description,
			Category:    val.Category,
		}
	}

	raw, err := yaml.Marshal(summary)
	if err != nil {
		vr.App().Flash().Errf("Error viewing kube-hunter report summary %vr ", err)
		return nil
	}

	details := NewDetails(vr.App(), "Summary", path, true).Update(string(raw))
	if err := vr.App().inject(details); err != nil {
		vr.App().Flash().Err(err)
	}

	return nil
}
