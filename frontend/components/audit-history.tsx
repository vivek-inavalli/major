"use client";

import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Trash2, Download, Loader } from "lucide-react";

interface AuditResult {
  id?: string;
  timestamp?: number;
  method: string;
  riskScore: number;
  riskLevel: "low" | "medium" | "high";
  detectedData: Record<string, number>;
  analysis: string;
}

export default function AuditHistory() {
  const [audits, setAudits] = useState<AuditResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadAudits = async () => {
      try {
        const response = await fetch("http://localhost:8000/audit");
        if (response.ok) {
          const data = await response.json();
          const auditList = data?.audits || [];

          const normalized: AuditResult[] = auditList.map((a: any) => ({
            id: a._id,
            timestamp: a.timestamp ? Date.parse(a.timestamp) : Date.now(),
            method: a.source?.type || "unknown",
            riskScore: a.risk?.score ?? 0,
            riskLevel: ((a.risk?.level || "low") as string).toLowerCase() as
              | "low"
              | "medium"
              | "high",
            detectedData: {},
            analysis: "",
          }));

          setAudits(
            normalized.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)),
          );
        }
      } catch (error) {
        console.error("[v0] Failed to load audits:", error);
      } finally {
        setLoading(false);
      }
    };

    loadAudits();
  }, []);

  const getRiskColor = (level: string) => {
    switch (level) {
      case "high":
        return "text-red-400 bg-red-400/10 border-red-400/30";
      case "medium":
        return "text-yellow-400 bg-yellow-400/10 border-yellow-400/30";
      case "low":
        return "text-green-400 bg-green-400/10 border-green-400/30";
      default:
        return "text-muted-foreground";
    }
  };

  const handleDelete = async (auditId: string | undefined) => {
    if (!auditId) return;
    try {
      const res = await fetch(`http://localhost:8000/audit/${auditId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setAudits((prev) => prev.filter((a) => a.id !== auditId));
      } else {
        console.error("[v0] Delete failed:", await res.text());
      }
    } catch (error) {
      console.error("[v0] Failed to delete audit:", error);
    }
  };

  const handleDownloadPDF = async (audit: AuditResult) => {
    if (!audit.id) return;
    try {
      const response = await fetch(
        `http://localhost:8000/audit/${audit.id}/report`,
      );
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `audit-${audit.timestamp || Date.now()}.pdf`;
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        console.error("[v0] PDF download failed:", await response.text());
      }
    } catch (error) {
      console.error("[v0] Failed to download PDF:", error);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12 text-muted-foreground flex items-center justify-center gap-2">
        <Loader className="w-4 h-4 animate-spin" />
        Loading audit history...
      </div>
    );
  }

  if (audits.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground mb-4">No audits yet</p>
        <p className="text-sm text-muted-foreground">
          Run your first audit to get started
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Recent Audits</h2>
      <div className="grid gap-4">
        {audits.map((audit, index) => (
          <Card
            key={audit.id || index}
            className="bg-card border-border p-6 hover:border-primary transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">
                      {audit.timestamp
                        ? new Date(audit.timestamp).toLocaleString()
                        : "Recently"}
                    </p>
                    <p className="text-sm text-muted-foreground capitalize mt-1">
                      {audit.method} Audit
                    </p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-semibold border ${getRiskColor(
                      audit.riskLevel,
                    )}`}
                  >
                    {(audit.riskLevel || "low").toUpperCase()} -{" "}
                    {audit.riskScore ?? 0}%
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  onClick={() => handleDownloadPDF(audit)}
                  size="sm"
                  variant="outline"
                  className="border-border hover:bg-muted"
                >
                  <Download className="w-4 h-4" />
                </Button>
                <Button
                  onClick={() => handleDelete(audit.id)}
                  size="sm"
                  variant="outline"
                  className="border-border hover:bg-destructive/10 hover:text-destructive"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
