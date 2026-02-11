import Image from "next/image";
import Link from "next/link";

const Footer = () => {
  return (
    <footer className="flex flex-col gap-10 px-4 md:px-6 mt-10">
      <div className="flex items-start flex-col-reverse gap-8 md:gap-0  md:flex-row md:items-center justify-between">
        <div className="flex flex-col justify-start gap-4 max-w-80">
          <div className="flex flex-col items-start gap-2">
            <Link
              aria-label="Go to home"
              className="w-fit hover:opacity-70 py-2 m-0 flex flex-row items-center gap-3"
              href="/"
            >
              <Image
                src="/official/logo.png"
                alt="logo"
                width={32}
                height={32}
              />
              Orafinite
            </Link>
            <p className="text-stone-500 dark:text-stone-600 font-normal text-sm ">
              Test vulnerabilities and protect your LLMs in real-time with
              Orafinite powered by Garak and LLM Guard.
            </p>
          </div>
          <p className="text-stone-400 font-normal text-xs ">
            © 2026 • Orafinite
          </p>
        </div>
        <p className=" text-[54px] md:text-[80px] font-thin text-stone-800 opacity-20 leading-120 md:leading-24 slashed-zero font-mono">
          42,000,451
        </p>
      </div>
      <div className="text-center">
        <p className="text-neutral-500">
          Designed and developed by{" "}
          <Link
            target="_blank"
            href="https://biki.com.np"
            className="text-white"
          >
            Admin12121
          </Link>
        </p>
      </div>
    </footer>
  );
};

export default Footer;
