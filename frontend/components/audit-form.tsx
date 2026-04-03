"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Upload, LinkIcon, FileText, Loader } from "lucide-react"

type AuditMethod = "url" | "text" | "file"

interface AuditFormProps {
  onSubmit: () => void
}

export default function AuditForm({ onSubmit }: AuditFormProps) {
  const router = useRouter()
  const [method, setMethod] = useState<AuditMethod>("text")
  const [url, setUrl] = useState("")
  const [text, setText] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const formData = new FormData()
      formData.append("method", method)

      if (method === "url") {
        if (!url.trim()) throw new Error("Please enter a URL")
        formData.append("url", url)
      } else if (method === "text") {
        if (!text.trim()) throw new Error("Please enter some text to audit")
        formData.append("text", text)
      } else if (method === "file") {
        if (!file) throw new Error("Please select a file")
        formData.append("file", file)
      }

      const response = await fetch("/api/audit", {
        method: "POST",
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Audit failed")
      }

      const result = await response.json()
      localStorage.setItem(`audit_${Date.now()}`, JSON.stringify(result))
      onSubmit()
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="bg-card border-border">
      <div className="p-8">
        <h2 className="text-2xl font-bold mb-6">Analyze Content</h2>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Method Selection */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { value: "url" as AuditMethod, label: "URL", icon: LinkIcon },
              { value: "text" as AuditMethod, label: "Text", icon: FileText },
              { value: "file" as AuditMethod, label: "File", icon: Upload },
            ].map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                type="button"
                onClick={() => setMethod(value)}
                className={`p-4 rounded-lg border-2 transition-all ${
                  method === value ? "border-primary bg-primary/10" : "border-border bg-background hover:border-muted"
                }`}
              >
                <Icon className="w-6 h-6 mx-auto mb-2" />
                <div className="text-sm font-medium">{label}</div>
              </button>
            ))}
          </div>

          {/* Input Section */}
          <div className="space-y-4">
            {method === "url" && (
              <div>
                <label className="block text-sm font-medium mb-2">URL</label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
            )}

            {method === "text" && (
              <div>
                <label className="block text-sm font-medium mb-2">Text Content</label>
                <textarea
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="Paste your text here for privacy analysis..."
                  rows={6}
                  className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary resize-none"
                />
              </div>
            )}

            {method === "file" && (
              <div>
                <label className="block text-sm font-medium mb-2">Upload File</label>
                <div
                  className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-primary transition-colors cursor-pointer"
                  onClick={() => document.getElementById("file-input")?.click()}
                >
                  <Upload className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="text-sm font-medium">Click to upload or drag and drop</p>
                  <p className="text-xs text-muted-foreground mt-1">TXT, PDF, or DOC files</p>
                </div>
                <input
                  id="file-input"
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="hidden"
                  accept=".txt,.pdf,.doc,.docx"
                />
                {file && <p className="text-sm text-muted-foreground mt-2">Selected: {file.name}</p>}
              </div>
            )}
          </div>

          {error && (
            <div className="p-3 bg-destructive/10 border border-destructive rounded-lg text-destructive text-sm">
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={loading}
            className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
          >
            {loading ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              "Run Audit"
            )}
          </Button>
        </form>
      </div>
    </Card>
  )
}
