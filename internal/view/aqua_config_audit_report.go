package view

import (
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/ui"
	"github.com/gdamore/tcell/v2"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"time"
)

type AquaSecurityConfigAuditReport struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		CreationTimestamp time.Time `yaml:"creationTimestamp"`
		Generation        int       `yaml:"generation"`
		Labels            struct {
			PluginConfigHash           string `yaml:"plugin-config-hash"`
			ResourceSpecHash           string `yaml:"resource-spec-hash"`
			StarboardResourceKind      string `yaml:"starboard.resource.kind"`
			StarboardResourceName      string `yaml:"starboard.resource.name"`
			StarboardResourceNamespace string `yaml:"starboard.resource.namespace"`
		} `yaml:"labels"`
		Name            string `yaml:"name"`
		Namespace       string `yaml:"namespace"`
		OwnerReferences []struct {
			APIVersion         string `yaml:"apiVersion"`
			BlockOwnerDeletion bool   `yaml:"blockOwnerDeletion"`
			Controller         bool   `yaml:"controller"`
			Kind               string `yaml:"kind"`
			Name               string `yaml:"name"`
			UID                string `yaml:"uid"`
		} `yaml:"ownerReferences"`
		ResourceVersion string `yaml:"resourceVersion"`
		UID             string `yaml:"uid"`
	} `yaml:"metadata"`
	Report struct {
		Checks []struct {
			Category string `yaml:"category"`
			CheckID  string `yaml:"checkID"`
			Message  string `yaml:"message"`
			Severity string `yaml:"severity"`
			Success  bool   `yaml:"success"`
			Scope    struct {
				Type  string `yaml:"type"`
				Value string `yaml:"value"`
			} `yaml:"scope,omitempty"`
		} `yaml:"checks"`
		ContainerChecks struct {
			Chartmuseum []struct {
				Category string `yaml:"category"`
				CheckID  string `yaml:"checkID"`
				Message  string `yaml:"message"`
				Scope    struct {
					Type  string `yaml:"type"`
					Value string `yaml:"value"`
				} `yaml:"scope"`
				Severity string `yaml:"severity"`
				Success  bool   `yaml:"success"`
			} `yaml:"chartmuseum"`
		} `yaml:"containerChecks"`
		PodChecks []struct {
			Category string `yaml:"category"`
			CheckID  string `yaml:"checkID"`
			Message  string `yaml:"message"`
			Severity string `yaml:"severity"`
			Success  bool   `yaml:"success"`
		} `yaml:"podChecks"`
		Scanner struct {
			Name    string `yaml:"name"`
			Vendor  string `yaml:"vendor"`
			Version string `yaml:"version"`
		} `yaml:"scanner"`
		Summary struct {
			DangerCount  int `yaml:"dangerCount"`
			PassCount    int `yaml:"passCount"`
			WarningCount int `yaml:"warningCount"`
		} `yaml:"summary"`
		UpdateTimestamp time.Time `yaml:"updateTimestamp"`
	} `yaml:"report"`
}

// ConfigAuditReport presents a secret viewer.
type ConfigAuditReport struct {
	ResourceViewer
}

// NewConfigAuditReport returns a new viewer.
func NewConfigAuditReport(gvr client.GVR) ResourceViewer {
	vr := ConfigAuditReport{
		ResourceViewer: NewBrowser(gvr),
	}
	vr.AddBindKeysFn(vr.bindKeys)

	return &vr
}

func (vr *ConfigAuditReport) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyX: ui.NewKeyAction("View Report Summary", vr.viewReport, true),
	})
}

func (vr *ConfigAuditReport) refCmd(evt *tcell.EventKey) *tcell.EventKey {
	return scanRefs(evt, vr.App(), vr.GetTable(), "aquasecurity.github.io/v1alpha1/ConfigAuditReport")
}

func (vr *ConfigAuditReport) viewReport(evt *tcell.EventKey) *tcell.EventKey {
	path := vr.GetTable().GetSelectedItem()
	if path == "" {
		return evt
	}

	r, err := vr.App().factory.Get(vr.GVR().String(), path, true, labels.Everything())
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	var report AquaSecurityConfigAuditReport
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(r.(*unstructured.Unstructured).Object, &report)
	if err != nil {
		vr.App().Flash().Err(err)
		return nil
	}

	crs := make(map[string]interface{})
	crs[report.Metadata.Name] = report.Report.Checks

	raw, err := yaml.Marshal(crs)
	if err != nil {
		vr.App().Flash().Errf("Error viewing config-audit report summary %vr ", err)
		return nil
	}

	details := NewDetails(vr.App(), "Summary", path, true).Update(string(raw))
	if err := vr.App().inject(details); err != nil {
		vr.App().Flash().Err(err)
	}

	return nil
}
