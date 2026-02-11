"use client";

import { useState, useEffect } from "react";
import {
  IconCpu,
  IconPlus,
  IconTrash,
  IconStar,
  IconStarFilled,
  IconInfoCircle,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  createModelConfig,
  listModelConfigs,
  deleteModelConfig,
  setDefaultModel,
} from "@/lib/actions/models";

interface ModelDisplay {
  id: string;
  name: string;
  provider: string;
  model: string;
  baseUrl: string | null;
  isDefault: boolean | null;
  createdAt: string;
}

// Provider configurations with examples and placeholders
const PROVIDERS = [
  {
    value: "openai",
    label: "OpenAI",
    placeholder: "gpt-4o, gpt-4-turbo, gpt-3.5-turbo",
    examples: "gpt-4o, gpt-4-turbo, gpt-4, gpt-3.5-turbo, o1-preview, o1-mini",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "anthropic",
    label: "Anthropic",
    placeholder: "claude-3-opus-20240229",
    examples:
      "claude-3-opus-20240229, claude-3-sonnet-20240229, claude-3-haiku-20240307",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "huggingface",
    label: "Hugging Face",
    placeholder: "meta-llama/Llama-2-70b-chat-hf",
    examples:
      "meta-llama/Llama-2-70b-chat-hf, mistralai/Mistral-7B-Instruct-v0.2, google/gemma-7b",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "ollama",
    label: "Ollama (Local)",
    placeholder: "llama2, mistral, codellama",
    examples:
      "llama2, llama3, mistral, codellama, phi, neural-chat, starling-lm",
    requiresApiKey: false,
    requiresBaseUrl: true,
    defaultBaseUrl: "http://localhost:11434",
  },
  {
    value: "groq",
    label: "Groq",
    placeholder: "llama-3.1-70b-versatile",
    examples:
      "llama-3.1-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "together",
    label: "Together AI",
    placeholder: "meta-llama/Llama-3-70b-chat-hf",
    examples:
      "meta-llama/Llama-3-70b-chat-hf, mistralai/Mixtral-8x7B-Instruct-v0.1",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "openrouter",
    label: "OpenRouter",
    placeholder: "anthropic/claude-3-opus",
    examples:
      "anthropic/claude-3-opus, openai/gpt-4-turbo, meta-llama/llama-3-70b",
    requiresApiKey: true,
    requiresBaseUrl: false,
  },
  {
    value: "custom",
    label: "Custom / Self-Hosted",
    placeholder: "your-model-name",
    examples: "Any OpenAI-compatible endpoint",
    requiresApiKey: false,
    requiresBaseUrl: true,
  },
];

export default function ModelsPage() {
  const [models, setModels] = useState<ModelDisplay[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [form, setForm] = useState({
    name: "",
    provider: "",
    model: "",
    apiKey: "",
    baseUrl: "",
  });

  const selectedProvider = PROVIDERS.find((p) => p.value === form.provider);

  useEffect(() => {
    loadModels();
  }, []);

  // Set default base URL when provider changes
  useEffect(() => {
    if (selectedProvider?.defaultBaseUrl && !form.baseUrl) {
      setForm((f) => ({
        ...f,
        baseUrl: selectedProvider.defaultBaseUrl || "",
      }));
    }
  }, [form.provider]);

  const loadModels = async () => {
    try {
      const result = await listModelConfigs();
      setModels(
        result.map((m) => ({
          id: m.id,
          name: m.name,
          provider: m.provider,
          model: m.model,
          baseUrl: m.baseUrl,
          isDefault: m.isDefault,
          createdAt: m.createdAt,
        })),
      );
    } catch (err) {
      console.error("Failed to load models:", err);
    }
  };

  const handleCreate = async () => {
    if (!form.name || !form.provider || !form.model) return;
    setIsCreating(true);
    try {
      await createModelConfig({
        name: form.name,
        provider: form.provider,
        model: form.model,
        apiKey: form.apiKey || undefined,
        baseUrl: form.baseUrl || undefined,
        isDefault: models.length === 0,
      });
      setForm({ name: "", provider: "", model: "", apiKey: "", baseUrl: "" });
      setShowCreate(false);
      loadModels();
    } catch (err) {
      console.error("Failed to create model:", err);
    } finally {
      setIsCreating(false);
    }
  };

  const handleDelete = async (modelId: string) => {
    try {
      await deleteModelConfig(modelId);
      loadModels();
    } catch (err) {
      console.error("Failed to delete model:", err);
    }
  };

  const handleSetDefault = async (modelId: string) => {
    try {
      await setDefaultModel(modelId);
      loadModels();
    } catch (err) {
      console.error("Failed to set default model:", err);
    }
  };

  const getProviderLabel = (value: string) => {
    return PROVIDERS.find((p) => p.value === value)?.label || value;
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">Model Registry</h1>
        <p className="text-sm text-neutral-400">
          Configure LLM models for vulnerability scanning with Garak
        </p>
      </div>

      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconCpu className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Model Configurations
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
          <Button
            size="sm"
            onClick={() => setShowCreate(!showCreate)}
            className="h-6 px-3 text-xs font-mono uppercase"
          >
            <IconPlus className="w-3 h-3 mr-1" />
            Add Model
          </Button>
        </div>

        {/* Create Form */}
        {showCreate && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <div className="grid grid-cols-2 gap-4">
              {/* Configuration Name */}
              <div className="space-y-2">
                <Label htmlFor="name">Configuration Name</Label>
                <Input
                  id="name"
                  placeholder="e.g., Production GPT-4o"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>

              {/* Provider */}
              <div className="space-y-2">
                <Label>Provider</Label>
                <Select
                  value={form.provider}
                  onValueChange={(v) =>
                    setForm({ ...form, provider: v, model: "", baseUrl: "" })
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select provider" />
                  </SelectTrigger>
                  <SelectContent>
                    {PROVIDERS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Model - Free form input with examples */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Label htmlFor="model">Model Identifier</Label>
                  {selectedProvider && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger>
                          <IconInfoCircle className="w-4 h-4 text-stone-500" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">
                          <p className="font-semibold mb-1">Examples:</p>
                          <p className="text-xs text-stone-400">
                            {selectedProvider.examples}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}
                </div>
                <Input
                  id="model"
                  placeholder={
                    selectedProvider?.placeholder || "Enter model identifier"
                  }
                  value={form.model}
                  onChange={(e) => setForm({ ...form, model: e.target.value })}
                  disabled={!form.provider}
                />
                {selectedProvider && (
                  <p className="text-xs text-stone-500">
                    e.g., {selectedProvider.examples.split(",")[0]}
                  </p>
                )}
              </div>

              {/* API Key */}
              <div className="space-y-2">
                <Label htmlFor="apiKey">
                  API Key {!selectedProvider?.requiresApiKey && "(optional)"}
                </Label>
                <Input
                  id="apiKey"
                  type="password"
                  placeholder={
                    selectedProvider?.requiresApiKey ? "Required" : "Optional"
                  }
                  value={form.apiKey}
                  onChange={(e) => setForm({ ...form, apiKey: e.target.value })}
                />
              </div>

              {/* Base URL - Show for providers that need it */}
              {(selectedProvider?.requiresBaseUrl ||
                form.provider === "custom") && (
                <div className="space-y-2 col-span-2">
                  <Label htmlFor="baseUrl">Base URL</Label>
                  <Input
                    id="baseUrl"
                    placeholder={
                      selectedProvider?.defaultBaseUrl ||
                      "https://your-api-endpoint.com"
                    }
                    value={form.baseUrl}
                    onChange={(e) =>
                      setForm({ ...form, baseUrl: e.target.value })
                    }
                  />
                  {form.provider === "ollama" && (
                    <p className="text-xs text-stone-500">
                      Default: http://localhost:11434 (Ollama local server)
                    </p>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="col-span-2 flex gap-2 pt-2">
                <Button
                  onClick={handleCreate}
                  disabled={
                    isCreating || !form.name || !form.provider || !form.model
                  }
                >
                  {isCreating ? "Creating..." : "Add Model"}
                </Button>
                <Button variant="ghost" onClick={() => setShowCreate(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Models List */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
          {models.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconCpu className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No models configured yet</p>
              <p className="text-xs mt-1">
                Add a model to start running vulnerability scans
              </p>
            </div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {models.map((model) => (
                <div
                  key={model.id}
                  className="p-4 flex items-center justify-between"
                >
                  <div className="flex items-center gap-4">
                    <button
                      onClick={() => handleSetDefault(model.id)}
                      className="text-stone-500 hover:text-yellow-500 transition-colors"
                      title={
                        model.isDefault ? "Default model" : "Set as default"
                      }
                    >
                      {model.isDefault ? (
                        <IconStarFilled className="w-5 h-5 text-yellow-500" />
                      ) : (
                        <IconStar className="w-5 h-5" />
                      )}
                    </button>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{model.name}</span>
                        {model.isDefault && (
                          <span className="text-xs bg-yellow-500/20 text-yellow-500 px-2 py-0.5 rounded">
                            Default
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-stone-500 flex items-center gap-2">
                        <span className="px-2 py-0.5 bg-zinc-800 rounded text-xs">
                          {getProviderLabel(model.provider)}
                        </span>
                        <span className="font-mono">{model.model}</span>
                        {model.baseUrl && (
                          <span className="text-xs text-stone-600">
                            • {model.baseUrl}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
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
                        <AlertDialogTitle>
                          Delete Model Configuration?
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                          This will remove the model configuration. Any scans
                          using this model will fail.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => handleDelete(model.id)}
                          className="bg-red-600 hover:bg-red-700"
                        >
                          Delete
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Provider Reference */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <IconInfoCircle className="w-4 h-4" />
            Supported Providers & Model Formats
          </h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            {PROVIDERS.map((provider) => (
              <div key={provider.value} className="p-3 bg-zinc-800 rounded-lg">
                <p className="font-medium text-stone-200">{provider.label}</p>
                <p className="text-xs text-stone-500 mt-1">
                  {provider.examples}
                </p>
                <div className="flex gap-2 mt-2">
                  {provider.requiresApiKey && (
                    <span className="text-xs bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded">
                      API Key Required
                    </span>
                  )}
                  {provider.requiresBaseUrl && (
                    <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                      Base URL Required
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
