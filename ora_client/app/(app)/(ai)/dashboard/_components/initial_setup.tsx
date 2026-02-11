import Image from "next/image";

export default function Initial_setup() {
  return (
    <div className="border border-zinc-800 rounded-2xl overflow-hidden">
      <div className="bg-zinc-900 px-6 py-4 border-b border-zinc-800">
        <p className="text-stone-800 font-medium text-base ">
          Welcome to Orafinite Security Suite
        </p>
        <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
          Follow these steps to configure your LLM and start testing for
          vulnerabilities with Garak and LLM Guard.
        </p>
      </div>
      <div className="bg-stone-0 bg-zinc-900">
        <div>
          <div>
            <div className="flex items-center justify-between gap-6 px-6 py-6">
              <div className="flex items-start gap-6 flex-1 w-1/2">
                <div className="size-8 rounded-full bg-stone-200 flex items-center justify-center shrink-0">
                  <p className="text-stone-800 font-medium text-base font-mono text-center">
                    1
                  </p>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center gap-4 mb-2">
                      <p className="text-stone-800 font-medium text-base ">
                        Add API Credentials
                      </p>
                      <span className="flex items-center gap-2">
                        <span className="size-2.5 border-[1.5px] rounded-full bg-rose-300 border-rose-700"></span>
                        <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
                          Not Configured
                        </span>
                      </span>
                    </div>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
                      Add your LLM provider API keys (OpenAI, HuggingFace,
                      Ollama, etc.).
                    </p>
                  </div>
                  <button
                    type="button"
                    className="group cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
        text-stone-50 bg-stone-700 border-2 border-stone-800 hover:bg-stone-800
        disabled:bg-stone-700 disabled:border-stone-800

        dark:border-stone-700 dark:bg-stone-900 dark:hover:bg-stone-700
      "
                    translate="no"
                  >
                    Add Credentials
                    <span className="-mr-1">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <path
                          d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          vectorEffect="non-scaling-stroke"
                        ></path>
                      </svg>
                    </span>
                  </button>
                </div>
              </div>
              <div className="flex-1 w-1/2">
                <div className="block dark:hidden">
                  <Image
                    width={100}
                    height={100}
                    alt="API Credentials"
                    src="/placeholder-credentials.png"
                  />
                </div>
                <div className="hidden dark:block">
                  <Image
                    width={100}
                    height={100}
                    alt="API Credentials"
                    src="/placeholder-credentials.png"
                  />
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between gap-6 px-6 py-6">
              <div className="flex items-start gap-6 flex-1 w-1/2">
                <div className="size-8 rounded-full bg-stone-200 flex items-center justify-center shrink-0">
                  <p className="text-stone-800 font-medium text-base font-mono text-center">
                    2
                  </p>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center gap-4 mb-2">
                      <p className="text-stone-800 font-medium text-base ">
                        Configure LLM Model
                      </p>
                      <span className="flex items-center gap-2">
                        <span className="size-2.5 border-[1.5px] rounded-full bg-rose-300 border-rose-700"></span>
                        <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
                          Not Set
                        </span>
                      </span>
                    </div>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
                      Select and configure the LLM model you want to test for
                      security vulnerabilities.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="group cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
        text-stone-50 bg-stone-700 border-2 border-stone-800 hover:bg-stone-800
        disabled:bg-stone-700 disabled:border-stone-800

        dark:border-stone-700 dark:bg-stone-900 dark:hover:bg-stone-700
      "
                    translate="no"
                  >
                    Configure Model
                    <span className="-mr-1">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <path
                          d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          vectorEffect="non-scaling-stroke"
                        ></path>
                      </svg>
                    </span>
                  </button>
                </div>
              </div>
              <div className="flex-1 w-1/2">
                <div className="block dark:hidden">
                  <Image
                    width={100}
                    height={100}
                    alt="Configure LLM Model"
                    src="/placeholder-model.png"
                  />
                </div>
                <div className="hidden dark:block">
                  <Image
                    width={100}
                    height={100}
                    alt="Configure LLM Model"
                    src="/placeholder-model.png"
                  />
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between gap-6 px-6 py-6">
              <div className="flex items-start gap-6 flex-1 w-1/2">
                <div className="size-8 rounded-full bg-stone-200 flex items-center justify-center shrink-0">
                  <p className="text-stone-800 font-medium text-base font-mono text-center">
                    3
                  </p>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center gap-4 mb-2">
                      <p className="text-stone-800 font-medium text-base ">
                        Test Connection
                      </p>
                      <span className="flex items-center gap-2">
                        <span className="size-2.5 border-[1.5px] rounded-full bg-rose-300 border-rose-700"></span>
                        <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
                          Not Tested
                        </span>
                      </span>
                    </div>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
                      Verify your LLM connection is working correctly before
                      running security scans.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="group cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
        text-stone-50 bg-stone-700 border-2 border-stone-800 hover:bg-stone-800
        disabled:bg-stone-700 disabled:border-stone-800

        dark:border-stone-700 dark:bg-stone-900 dark:hover:bg-stone-700
      "
                    translate="no"
                  >
                    Test Connection
                    <span className="-mr-1">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <path
                          d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          vectorEffect="non-scaling-stroke"
                        ></path>
                      </svg>
                    </span>
                  </button>
                </div>
              </div>
              <div className="flex-1 w-1/2">
                <div className="block dark:hidden">
                  <Image
                    width={100}
                    height={100}
                    alt="Test Connection"
                    src="/placeholder-test.png"
                  />
                </div>
                <div className="hidden dark:block">
                  <Image
                    width={100}
                    height={100}
                    alt="Test Connection"
                    src="/placeholder-test.png"
                  />
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between gap-6 px-6 py-6">
              <div className="flex items-start gap-6 flex-1 w-1/2">
                <div className="size-8 rounded-full bg-stone-200 flex items-center justify-center shrink-0">
                  <p className="text-stone-800 font-medium text-base font-mono text-center">
                    4
                  </p>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center gap-4 mb-2">
                      <p className="text-stone-800 font-medium text-base ">
                        Run Security Scan
                      </p>
                      <span className="flex items-center gap-2">
                        <span className="size-2.5 border-[1.5px] rounded-full bg-rose-300 border-rose-700"></span>
                        <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
                          PENDING
                        </span>
                      </span>
                    </div>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
                      Launch your first Garak vulnerability scan to test prompt
                      injection, jailbreaks, and more.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="group cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
        text-stone-50 bg-stone-700 border-2 border-stone-800 hover:bg-stone-800
        disabled:bg-stone-700 disabled:border-stone-800

        dark:border-stone-700 dark:bg-stone-900 dark:hover:bg-stone-700
      "
                    translate="no"
                  >
                    Start Scan
                    <span className="-mr-1">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <path
                          d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          vectorEffect="non-scaling-stroke"
                        ></path>
                      </svg>
                    </span>
                  </button>
                </div>
              </div>
              <div className="flex-1 w-1/2">
                <div className="block dark:hidden">
                  <Image
                    width={100}
                    height={100}
                    alt="Run Security Scan"
                    src="/placeholder-scan.png"
                  />
                </div>
                <div className="hidden dark:block">
                  <Image
                    width={100}
                    height={100}
                    alt="Run Security Scan"
                    src="/placeholder-scan.png"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
