"use client";

import { useState, useEffect } from "react";
import {
  IconKey,
  IconPlus,
  IconTrash,
  IconCopy,
  IconCheck,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  createApiKey,
  listApiKeys,
  revokeApiKey,
} from "@/lib/actions/api-keys";

interface ApiKeyDisplay {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: Date;
  lastUsedAt: Date | null;
}

// Code snippets for different languages
const CODE_SNIPPETS = {
  curl: `curl --location 'http://localhost:8080/v1/guard/scan' \\
--header 'X-API-Key: YOUR_API_KEY' \\
--header 'Content-Type: application/json' \\
--data '{
  "prompt": "Your prompt to scan for threats",
  "options": {
    "check_injection": true,
    "check_toxicity": true,
    "check_pii": true,
    "sanitize": false
  }
}'`,
  nodejs: `const response = await fetch('http://localhost:8080/v1/guard/scan', {
  method: 'POST',
  headers: {
    'X-API-Key': 'YOUR_API_KEY',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    prompt: 'Your prompt to scan for threats',
    options: {
      check_injection: true,
      check_toxicity: true,
      check_pii: true,
      sanitize: false,
    },
  }),
});

const result = await response.json();
console.log(result.safe ? 'Safe!' : 'Threats detected:', result.threats);`,
  python: `import requests

response = requests.post(
    'http://localhost:8080/v1/guard/scan',
    headers={
        'X-API-Key': 'YOUR_API_KEY',
        'Content-Type': 'application/json',
    },
    json={
        'prompt': 'Your prompt to scan for threats',
        'options': {
            'check_injection': True,
            'check_toxicity': True,
            'check_pii': True,
            'sanitize': False,
        },
    },
)

result = response.json()
print('Safe!' if result['safe'] else f"Threats: {result['threats']}")`,
  rust: `use reqwest::Client;
use serde_json::json;

let client = Client::new();
let response = client
    .post("http://localhost:8080/v1/guard/scan")
    .header("X-API-Key", "YOUR_API_KEY")
    .header("Content-Type", "application/json")
    .json(&json!({
        "prompt": "Your prompt to scan for threats",
        "options": {
            "check_injection": true,
            "check_toxicity": true,
            "check_pii": true,
            "sanitize": false
        }
    }))
    .send()
    .await?;

let result: serde_json::Value = response.json().await?;
println!("{:?}", result);`,
  go: `package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

func main() {
    payload := map[string]interface{}{
        "prompt": "Your prompt to scan for threats",
        "options": map[string]bool{
            "check_injection": true,
            "check_toxicity":  true,
            "check_pii":       true,
            "sanitize":        false,
        },
    }

    body, _ := json.Marshal(payload)
    req, _ := http.NewRequest("POST", "http://localhost:8080/v1/guard/scan", bytes.NewBuffer(body))
    req.Header.Set("X-API-Key", "YOUR_API_KEY")
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, _ := client.Do(req)
    defer resp.Body.Close()
}`,
  php: `<?php
$ch = curl_init();

curl_setopt_array($ch, [
    CURLOPT_URL => 'http://localhost:8080/v1/guard/scan',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'X-API-Key: YOUR_API_KEY',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'prompt' => 'Your prompt to scan for threats',
        'options' => [
            'check_injection' => true,
            'check_toxicity' => true,
            'check_pii' => true,
            'sanitize' => false,
        ],
    ]),
]);

$response = curl_exec($ch);
$result = json_decode($response, true);
curl_close($ch);

echo $result['safe'] ? 'Safe!' : 'Threats detected';`,
  csharp: `using System.Net.Http;
using System.Text;
using System.Text.Json;

var client = new HttpClient();
var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:8080/v1/guard/scan");
request.Headers.Add("X-API-Key", "YOUR_API_KEY");

var payload = new {
    prompt = "Your prompt to scan for threats",
    options = new {
        check_injection = true,
        check_toxicity = true,
        check_pii = true,
        sanitize = false
    }
};

request.Content = new StringContent(
    JsonSerializer.Serialize(payload),
    Encoding.UTF8,
    "application/json"
);

var response = await client.SendAsync(request);
var result = await response.Content.ReadAsStringAsync();
Console.WriteLine(result);`,
  java: `import java.net.http.*;
import java.net.URI;

HttpClient client = HttpClient.newHttpClient();

String json = """
    {
      "prompt": "Your prompt to scan for threats",
      "options": {
        "check_injection": true,
        "check_toxicity": true,
        "check_pii": true,
        "sanitize": false
      }
    }
    """;

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("http://localhost:8080/v1/guard/scan"))
    .header("X-API-Key", "YOUR_API_KEY")
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json))
    .build();

HttpResponse<String> response = client.send(request,
    HttpResponse.BodyHandlers.ofString());
System.out.println(response.body());`,
};

const LANGUAGES = [
  {
    id: "curl",
    name: "cURL",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/bash.svg",
  },
  {
    id: "nodejs",
    name: "NodeJS",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/nodejs.svg",
  },
  {
    id: "python",
    name: "Python",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/python.svg",
  },
  {
    id: "rust",
    name: "Rust",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/rust.svg",
    darkInvert: true,
  },
  {
    id: "go",
    name: "Go",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/go.svg",
  },
  {
    id: "php",
    name: "PHP",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/php.svg",
  },
  {
    id: "csharp",
    name: "C#",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/csharp.svg",
  },
  {
    id: "java",
    name: "Java",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/java.svg",
  },
];

export default function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyDisplay[]>([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedLang, setSelectedLang] = useState("curl");
  const [codeCopied, setCodeCopied] = useState(false);

  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    try {
      const result = await listApiKeys();
      setKeys(
        result.map((k) => ({
          id: k.id,
          name: k.name,
          keyPrefix: k.keyPrefix,
          createdAt: new Date(k.createdAt),
          lastUsedAt: k.lastUsedAt ? new Date(k.lastUsedAt) : null,
        })),
      );
    } catch (err) {
      console.error("Failed to load API keys:", err);
    }
  };

  const handleCreate = async () => {
    if (!newKeyName.trim()) return;
    setIsCreating(true);
    try {
      const result = await createApiKey(newKeyName);
      setNewKey(result.key);
      setNewKeyName("");
      loadKeys();
    } catch (err) {
      console.error("Failed to create API key:", err);
    } finally {
      setIsCreating(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    try {
      await revokeApiKey(keyId);
      loadKeys();
    } catch (err) {
      console.error("Failed to revoke API key:", err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyCode = () => {
    navigator.clipboard.writeText(
      CODE_SNIPPETS[selectedLang as keyof typeof CODE_SNIPPETS],
    );
    setCodeCopied(true);
    setTimeout(() => setCodeCopied(false), 2000);
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">API Credentials</h1>
        <p className="text-sm text-neutral-400">
          Manage API keys for programmatic access to the LLM Guard API
        </p>
      </div>

      {/* Create New Key */}
      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconKey className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              API Keys
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
          <Button
            size="sm"
            onClick={() => setShowCreate(!showCreate)}
            className="h-6 px-3 text-xs font-mono uppercase"
          >
            <IconPlus className="w-3 h-3 mr-1" />
            New Key
          </Button>
        </div>

        {/* New Key Form */}
        {showCreate && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <div className="flex flex-col gap-4">
              <div className="space-y-2">
                <Label htmlFor="keyName">Key Name</Label>
                <Input
                  id="keyName"
                  placeholder="e.g., Production API Key"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                />
              </div>
              <Button
                onClick={handleCreate}
                disabled={!newKeyName.trim() || isCreating}
                className="w-fit"
              >
                {isCreating ? "Creating..." : "Create API Key"}
              </Button>
            </div>
          </div>
        )}

        {/* Show New Key (only once) */}
        {newKey && (
          <div className="bg-lime-900/20 border border-lime-700 rounded-2xl p-6">
            <div className="flex flex-col gap-4">
              <p className="text-lime-400 text-sm font-semibold">
                API Key Created Successfully!
              </p>
              <p className="text-stone-400 text-xs">
                Copy this key now. You won&apos;t be able to see it again.
              </p>
              <div className="flex gap-2 items-center">
                <code className="flex-1 bg-zinc-800 px-4 py-2 rounded-lg font-mono text-sm break-all">
                  {newKey}
                </code>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => copyToClipboard(newKey)}
                >
                  {copied ? (
                    <IconCheck className="w-4 h-4" />
                  ) : (
                    <IconCopy className="w-4 h-4" />
                  )}
                </Button>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setNewKey(null);
                  setShowCreate(false);
                }}
                className="w-fit"
              >
                Done
              </Button>
            </div>
          </div>
        )}

        {/* Keys List */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
          {keys.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconKey className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No API keys yet</p>
              <p className="text-xs mt-1">
                Create one to start using the Guard API
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="border-b border-zinc-800">
                <tr className="text-left text-xs font-mono uppercase text-stone-500">
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Key</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Last Used</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => (
                  <tr
                    key={key.id}
                    className="border-b border-zinc-800 last:border-0"
                  >
                    <td className="px-4 py-3 font-medium">{key.name}</td>
                    <td className="px-4 py-3">
                      <code className="text-stone-500 font-mono text-sm">
                        {key.keyPrefix}...
                      </code>
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {new Date(key.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {key.lastUsedAt
                        ? new Date(key.lastUsedAt).toLocaleDateString()
                        : "Never"}
                    </td>
                    <td className="px-4 py-3">
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-500 hover:text-red-400"
                          >
                            <IconTrash className="w-4 h-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Revoke API Key?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will immediately invalidate the key. Any
                              applications using this key will stop working.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => handleRevoke(key.id)}
                              className="bg-red-600 hover:bg-red-700"
                            >
                              Revoke Key
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Usage Instructions - Multi-language Code Snippets */}
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconKey className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              How to use your API key
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="flex border border-zinc-800 rounded-2xl overflow-hidden">
          {/* Language Tabs */}
          <div className="flex flex-col border-r border-zinc-800 bg-zinc-900/50">
            {LANGUAGES.map((lang) => (
              <button
                key={lang.id}
                type="button"
                onClick={() => setSelectedLang(lang.id)}
                className={`flex items-center gap-3 px-4 py-3 border-b border-zinc-800 last:border-b-0 transition-colors duration-200 ease cursor-pointer ${
                  selectedLang === lang.id
                    ? "bg-zinc-800"
                    : "bg-zinc-900/50 hover:bg-zinc-800/50"
                }`}
              >
                <img
                  alt={lang.name}
                  className={`w-5 h-5 ${lang.darkInvert ? "dark:invert" : ""}`}
                  src={lang.icon}
                />
                <span
                  className={`text-sm font-medium ${
                    selectedLang === lang.id
                      ? "text-stone-200"
                      : "text-stone-500"
                  }`}
                >
                  {lang.name}
                </span>
              </button>
            ))}
          </div>

          {/* Code Display */}
          <div className="flex-1 bg-zinc-900 relative">
            <div className="absolute top-4 right-4 z-10">
              <Button
                size="sm"
                variant="secondary"
                onClick={copyCode}
                className="h-6 px-3 text-xs font-mono uppercase"
              >
                {codeCopied ? (
                  <>
                    <IconCheck className="w-4 h-4 mr-1" />
                    Copied
                  </>
                ) : (
                  <>
                    <IconCopy className="w-4 h-4 mr-1" />
                    Copy
                  </>
                )}
              </Button>
            </div>
            <div className="overflow-auto p-6 max-h-[450px] min-h-[450px]">
              <pre className="whitespace-pre text-sm">
                <code className="text-stone-300 font-mono">
                  {CODE_SNIPPETS[selectedLang as keyof typeof CODE_SNIPPETS]}
                </code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
