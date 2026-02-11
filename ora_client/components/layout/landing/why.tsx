const Why = () => {
  return (
    <div className="flex flex-col gap-6 items-center mt-30">
      <div className="flex flex-col gap-4 items-center lg:px-6 px-4">
        <p className="text-stone-800 font-normal text-xs uppercase font-mono leading-4">
          Why Orafinite
        </p>
        <p className="text-stone-800 font-normal text-2xl text-center cooper lg:whitespace-pre-line">
          Everything you need to secure your AI,
          <br /> test vulnerabilities, and protect in real-time!
        </p>
      </div>
      <ul className="grid w-full grid-cols-2 lg:grid-cols-3 border-t border-b lg:border-b-stone-50  divide-x  divide-y border-dashed divide-dashed">
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50 border-dashed">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M21.5 4.5C21.5 5.60457 20.6046 6.5 19.5 6.5C18.3954 6.5 17.5 5.60457 17.5 4.5C17.5 3.39543 18.3954 2.5 19.5 2.5C20.6046 2.5 21.5 3.39543 21.5 4.5Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M20.4711 9.40577C20.5 10.2901 20.5 11.3119 20.5 12.5C20.5 16.7426 20.5 18.864 19.182 20.182C17.864 21.5 15.7426 21.5 11.5 21.5C7.25736 21.5 5.13604 21.5 3.81802 20.182C2.5 18.864 2.5 16.7426 2.5 12.5C2.5 8.25736 2.5 6.13604 3.81802 4.81802C5.13604 3.5 7.25736 3.5 11.5 3.5C12.6881 3.5 13.7099 3.5 14.5942 3.52895"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M6.5 14.5L9.29289 11.7071C9.68342 11.3166 10.3166 11.3166 10.7071 11.7071L12.2929 13.2929C12.6834 13.6834 13.3166 13.6834 13.7071 13.2929L16.5 10.5"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                REAL-TIME THREAT DETECTION
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Monitor every prompt in real-time—blocked, flagged, or
                allowed—with detailed security logs and instant alerts.
              </p>
            </div>
          </div>
        </li>
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50 border-dashed">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M5.00035 7L3.78154 7.81253C2.90783 8.39501 2.47097 8.68625 2.23422 9.13041C1.99747 9.57457 1.99923 10.0966 2.00273 11.1406C2.00696 12.3975 2.01864 13.6782 2.05099 14.9741C2.12773 18.0487 2.16611 19.586 3.29651 20.7164C4.42691 21.8469 5.98497 21.8858 9.10108 21.9637C11.0397 22.0121 12.9611 22.0121 14.8996 21.9637C18.0158 21.8858 19.5738 21.8469 20.7042 20.7164C21.8346 19.586 21.873 18.0487 21.9497 14.9741C21.9821 13.6782 21.9937 12.3975 21.998 11.1406C22.0015 10.0966 22.0032 9.57456 21.7665 9.13041C21.5297 8.68625 21.0929 8.39501 20.2191 7.81253L19.0003 7"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M2 10L8.91302 14.1478C10.417 15.0502 11.169 15.5014 12 15.5014C12.831 15.5014 13.583 15.0502 15.087 14.1478L22 10"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M5 12V6C5 4.11438 5 3.17157 5.58579 2.58579C6.17158 2 7.11439 2 9 2H15C16.8856 2 17.8284 2 18.4142 2.58579C19 3.17157 19 4.11438 19 6V12"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M10 10H14M10 6H14"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                VULNERABILITY INSIGHTS
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Track attack success rates, vulnerability categories, and risk
                scores so you know exactly where your AI is weak.
              </p>
            </div>
          </div>
        </li>
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M16 3H8C5.17157 3 3.75736 3 2.87868 3.87868C2 4.75736 2 6.17157 2 9V11C2 13.8284 2 15.2426 2.87868 16.1213C3.75736 17 5.17157 17 8 17H16C18.8284 17 20.2426 17 21.1213 16.1213C22 15.2426 22 13.8284 22 11V9C22 6.17157 22 4.75736 21.1213 3.87868C20.2426 3 18.8284 3 16 3Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M14 9C14 7.89543 13.1046 7 12 7C10.8954 7 10 7.89543 10 9H9.5C8.39543 9 7.5 9.89543 7.5 11C7.5 12.1046 8.39543 13 9.5 13H14.5C15.6046 13 16.5 12.1046 16.5 11C16.5 9.89543 15.6046 9 14.5 9H14Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M14 21H16M14 21C13.1716 21 12.5 20.3284 12.5 19.5V17H12M14 21H10M12 17H11.5V19.5C11.5 20.3284 10.8284 21 10 21M12 17V21M10 21H8"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                MULTI-PROVIDER SUPPORT
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Test and protect any LLM—OpenAI, HuggingFace, Ollama, or custom
                models with unified security across all providers.
              </p>
            </div>
          </div>
        </li>
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
              >
                <path
                  d="M2 5L8.91302 8.92462C11.4387 10.3585 12.5613 10.3585 15.087 8.92462L22 5"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M21.9928 11C22.0047 10.1743 22.0019 10.3514 21.9842 9.52439C21.9189 6.45886 21.8862 4.92609 20.7551 3.79066C19.6239 2.65523 18.0497 2.61568 14.9012 2.53657C12.9607 2.48781 11.0393 2.48781 9.09882 2.53656C5.95033 2.61566 4.37608 2.65521 3.24495 3.79065C2.11382 4.92608 2.08114 6.45885 2.01576 9.52438C1.99474 10.5101 1.99475 11.4899 2.01577 12.4756C2.08114 15.5412 2.11383 17.0739 3.24496 18.2094C4.37608 19.3448 5.95033 19.3843 9.09883 19.4634C10.0691 19.4878 10.0345 19.5 11 19.5"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M14 14.5L17.5 18M17.5 18L21 21.5M17.5 18L14 21.5M17.5 18L21 14.5"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                PROMPT INJECTION BLOCKING
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Automatically block malicious prompts, jailbreak attempts, and
                manipulation attacks before they reach your model.
              </p>
            </div>
          </div>
        </li>
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M18.9905 19H19M18.9905 19C18.3678 19.6175 17.2393 19.4637 16.4479 19.4637C15.4765 19.4637 15.0087 19.6537 14.3154 20.347C13.7251 20.9374 12.9337 22 12 22C11.0663 22 10.2749 20.9374 9.68457 20.347C8.99128 19.6537 8.52349 19.4637 7.55206 19.4637C6.76068 19.4637 5.63218 19.6175 5.00949 19C4.38181 18.3776 4.53628 17.2444 4.53628 16.4479C4.53628 15.4414 4.31616 14.9786 3.59938 14.2618C2.53314 13.1956 2.00002 12.6624 2 12C2.00001 11.3375 2.53312 10.8044 3.59935 9.73817C4.2392 9.09832 4.53628 8.46428 4.53628 7.55206C4.53628 6.76065 4.38249 5.63214 5 5.00944C5.62243 4.38178 6.7556 4.53626 7.55208 4.53626C8.46427 4.53626 9.09832 4.2392 9.73815 3.59937C10.8044 2.53312 11.3375 2 12 2C12.6625 2 13.1956 2.53312 14.2618 3.59937C14.9015 4.23907 15.5355 4.53626 16.4479 4.53626C17.2393 4.53626 18.3679 4.38247 18.9906 5C19.6182 5.62243 19.4637 6.75559 19.4637 7.55206C19.4637 8.55858 19.6839 9.02137 20.4006 9.73817C21.4669 10.8044 22 11.3375 22 12C22 12.6624 21.4669 13.1956 20.4006 14.2618C19.6838 14.9786 19.4637 15.4414 19.4637 16.4479C19.4637 17.2444 19.6182 18.3776 18.9905 19Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M9 12.8929C9 12.8929 10.2 13.5447 10.8 14.5C10.8 14.5 12.6 10.75 15 9.5"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                PII & DATA LEAK PROTECTION
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Detect and redact sensitive data like emails, phone numbers, and
                credentials before they leak through your AI responses.
              </p>
            </div>
          </div>
        </li>
        <li className="[&amp;:nth-last-child(2)]:border-b-stone-50 lg:[&amp;:nth-last-child(2)]:border-b-stone-200 last:lg:border-b  h-full flex flex-col last:border-r [&amp;:nth-child(2n)]:border-r-stone-50 [&amp;:nth-child(2n)]:lg:border-r-stone-200 lg:[&amp;:nth-child(3n)]:lg:border-r-stone-50 border-dashed">
          <div className=" flex flex-col gap-4 py-6 px-4 lg:px-6">
            <span className="text-stone-800">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M18.5 3H5.5C5.03534 3 4.80302 3 4.60982 3.03843C3.81644 3.19624 3.19624 3.81644 3.03843 4.60982C3 4.80302 3 5.03534 3 5.5C3 5.96466 3 6.19698 3.03843 6.39018C3.19624 7.18356 3.81644 7.80376 4.60982 7.96157C4.80302 8 5.03534 8 5.5 8H18.5C18.9647 8 19.197 8 19.3902 7.96157C20.1836 7.80376 20.8038 7.18356 20.9616 6.39018C21 6.19698 21 5.96466 21 5.5C21 5.03534 21 4.80302 20.9616 4.60982C20.8038 3.81644 20.1836 3.19624 19.3902 3.03843C19.197 3 18.9647 3 18.5 3Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M18.5 11H5.5C5.03534 11 4.80302 11 4.60982 11.0384C3.81644 11.1962 3.19624 11.8164 3.03843 12.6098C3 12.803 3 13.0353 3 13.5C3 13.9647 3 14.197 3.03843 14.3902C3.19624 15.1836 3.81644 15.8038 4.60982 15.9616C4.80302 16 5.03534 16 5.5 16H18.5C18.9647 16 19.197 16 19.3902 15.9616C20.1836 15.8038 20.8038 15.1836 20.9616 14.3902C21 14.197 21 13.9647 21 13.5C21 13.0353 21 12.803 20.9616 12.6098C20.8038 11.8164 20.1836 11.1962 19.3902 11.0384C19.197 11 18.9647 11 18.5 11Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M12 19V21M5 21H19"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M6 13.5H6.01"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M6 5.5H6.01"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M9 13.5H9.01"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
                <path
                  d="M9 5.5H9.01"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
            <div className="flex flex-col gap-2">
              <p className="text-stone-800 font-medium text-sm font-mono leading-5 uppercase">
                GARAK INTEGRATION
              </p>
              <p className="text-stone-500 dark:text-stone-600 font-normal text-sm leading-5 text-justify">
                Run 150+ automated attack probes against your LLM with Garak—the
                industry standard for AI red-teaming and vulnerability testing.
              </p>
            </div>
          </div>
        </li>
      </ul>
    </div>
  );
};

export default Why;
