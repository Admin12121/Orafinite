"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { twoFactor } from "@/lib/auth-client";
import { IconLoader2, IconShieldCheck } from "@tabler/icons-react";

export default function TwoFactorPage() {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [useBackupCode, setUseBackupCode] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      if (useBackupCode) {
        const result = await twoFactor.verifyBackupCode({ code });
        if (result.error) {
          setError(result.error.message || "Invalid backup code");
          return;
        }
      } else {
        const result = await twoFactor.verifyTotp({ code });
        if (result.error) {
          setError(result.error.message || "Invalid verification code");
          return;
        }
      }
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-svh w-full items-center justify-center p-6 md:p-10">
      <div className="w-full max-w-sm">
        <div className={cn("flex flex-col bg-neutral-800 rounded-xl")}>
          <Card className="pb-6 ring-0">
            <CardHeader className="text-center flex items-center flex-col">
              <div className="mb-4 p-3 rounded-full bg-neutral-700">
                <IconShieldCheck className="w-8 h-8 text-green-500" />
              </div>
              <CardTitle className="text-xl">
                Two-Factor Authentication
              </CardTitle>
              <CardDescription>
                {useBackupCode
                  ? "Enter one of your backup codes"
                  : "Enter the 6-digit code from your authenticator app"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="code">
                    {useBackupCode ? "Backup Code" : "Verification Code"}
                  </Label>
                  <Input
                    id="code"
                    type="text"
                    placeholder={useBackupCode ? "XXXX-XXXX" : "000000"}
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    required
                    autoComplete="one-time-code"
                    inputMode={useBackupCode ? "text" : "numeric"}
                    pattern={useBackupCode ? undefined : "[0-9]{6}"}
                    maxLength={useBackupCode ? 10 : 6}
                    className="text-center text-2xl tracking-widest"
                  />
                </div>

                {error && (
                  <p className="text-sm text-red-500 text-center">{error}</p>
                )}

                <Button type="submit" className="w-full" disabled={isLoading}>
                  {isLoading && <IconLoader2 className="animate-spin mr-2" />}
                  Verify
                </Button>
              </form>

              <div className="mt-4 text-center">
                <button
                  type="button"
                  className="text-sm text-neutral-400 hover:text-white"
                  onClick={() => {
                    setUseBackupCode(!useBackupCode);
                    setCode("");
                    setError(null);
                  }}
                >
                  {useBackupCode
                    ? "Use authenticator app instead"
                    : "Use a backup code instead"}
                </button>
              </div>
            </CardContent>
          </Card>

          <div className="text-center p-4">
            <button
              type="button"
              className="text-sm text-neutral-500 hover:text-white"
              onClick={() => router.push("/login")}
            >
              Back to login
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
