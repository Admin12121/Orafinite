import Analytics from "./_components";
import Initial_setup from "./_components/initial_setup";
import GarakSummary from "./_components/garak-summary";

export default function page() {
  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div className="">
        <h1 className="text-xl font-bold">Security Dashboard</h1>
        <p className="text-sm text-neutral-400">
          Monitor LLM vulnerabilities, threat detection, and security scan
          results
        </p>
      </div>
      <Initial_setup />
      <Analytics />
      <GarakSummary />
    </section>
  );
}
