const Demo = () => {
  return (
    <div className="flex flex-col w-full  gap-6 mt-30">
      <div className="flex flex-col gap-2 items-center px-4 lg:px-0">
        <p className="text-stone-800 font-normal text-xs uppercase font-mono leading-4 text-center">
          Security metrics (real-time)
        </p>
        <p className="text-stone-800 font-normal text-2xl cooper text-center">
          AI protection you can trust
        </p>
      </div>
      <ul className="grid lg:grid-cols-3 border-y  grid-cols-1 divide-dashed divide-y lg:divide-y-0 lg:divide-x  border-dashed">
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">50-70ms</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              RESPONSE TIME
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              Average latency for LLM Guard to scan and validate prompts before
              they reach your model.
            </p>
          </div>
        </li>
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">99.2%</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              THREATS BLOCKED
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              Percentage of prompt injections, jailbreaks, and malicious inputs
              detected and blocked in real-time.
            </p>
          </div>
        </li>
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">150+</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              ATTACK VECTORS
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              Number of vulnerability probes tested by Garak including prompt
              injection, data leakage, and jailbreaks.
            </p>
          </div>
        </li>
      </ul>
    </div>
  );
};

export default Demo;
