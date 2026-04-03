import { type NextRequest, NextResponse } from "next/server"

const BACKEND_URL = "http://localhost:8000"

interface AuditResult {
  id?: string
  method: string
  riskScore: number
  riskLevel: "low" | "medium" | "high"
  detectedData: Record<string, number>
  analysis: string
}

async function analyzeContent(method: string, content: string | File, url?: string): Promise<AuditResult> {
  try {
    let response: Response

    if (method === "url" && url) {
      response = await fetch(`${BACKEND_URL}/audit/url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      })
    } else if (method === "text" && typeof content === "string") {
      response = await fetch(`${BACKEND_URL}/audit/text`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text: content }),
      })
    } else if (method === "file" && content instanceof File) {
      const formData = new FormData()
      formData.append("file", content)

      response = await fetch(`${BACKEND_URL}/audit/upload`, {
        method: "POST",
        body: formData,
      })
    } else {
      throw new Error("Invalid method or content type")
    }

    if (!response.ok) {
      throw new Error(`Backend error: ${response.statusText}`)
    }

    const result = await response.json()
    return result as AuditResult
  } catch (error) {
    console.error("[v0] Backend call failed:", error)
    throw error
  }
}

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const method = formData.get("method") as string
    let content: string | File = ""
    let url: string | undefined

    if (method === "url") {
      url = formData.get("url") as string
      if (!url) {
        return NextResponse.json({ error: "URL is required" }, { status: 400 })
      }
    } else if (method === "text") {
      content = formData.get("text") as string
      if (!content) {
        return NextResponse.json({ error: "Text content is required" }, { status: 400 })
      }
    } else if (method === "file") {
      const file = formData.get("file") as File
      if (!file) {
        return NextResponse.json({ error: "File is required" }, { status: 400 })
      }
      content = file
    }

    const result = await analyzeContent(method, content, url)
    return NextResponse.json(result)
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Analysis failed" }, { status: 500 })
  }
}
