"use client"

import { useState } from "react"
import { Shield, Lock, Zap } from "lucide-react"
import AuditForm from "@/components/audit-form"
import AuditHistory from "@/components/audit-history"

export default function Home() {
  const [activeTab, setActiveTab] = useState<"audit" | "history">("audit")
  const [refreshHistory, setRefreshHistory] = useState(0)

  const handleAuditSubmit = () => {
    setRefreshHistory((prev) => prev + 1)
    setActiveTab("history")
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold">Privacy Audit</h1>
          </div>
          <p className="text-muted-foreground mt-2">Detect sensitive data and privacy risks in your content</p>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex gap-8">
            <button
              onClick={() => setActiveTab("audit")}
              className={`py-4 px-2 border-b-2 transition-colors ${
                activeTab === "audit"
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              New Audit
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`py-4 px-2 border-b-2 transition-colors ${
                activeTab === "history"
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              Audit History
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {activeTab === "audit" ? (
          <div className="grid md:grid-cols-3 gap-12">
            <div className="md:col-span-2">
              <AuditForm onSubmit={handleAuditSubmit} />
            </div>
            <div className="space-y-4">
              <div className="bg-card rounded-lg p-6 border border-border">
                <div className="flex items-start gap-3">
                  <Lock className="w-5 h-5 text-accent mt-1" />
                  <div>
                    <h3 className="font-semibold">Secure & Private</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Your data is processed securely and never stored
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-card rounded-lg p-6 border border-border">
                <div className="flex items-start gap-3">
                  <Zap className="w-5 h-5 text-accent mt-1" />
                  <div>
                    <h3 className="font-semibold">AI-Powered</h3>
                    <p className="text-sm text-muted-foreground mt-1">Advanced detection of sensitive information</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <AuditHistory key={refreshHistory} />
        )}
      </div>
    </main>
  )
}
