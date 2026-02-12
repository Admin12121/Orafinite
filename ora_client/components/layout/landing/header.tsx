// import ThemeSwitch from "@/components/table-columns/theme-switch";
import { Button } from "@/components/ui/button";
// import { CircleOpenArrowRight } from "@/icons";
// import { LINKS } from "@/constants/links";
import Image from "next/image";
import Link from "next/link";
import { ModeSwitcher } from "./mode-switch";

const Header = () => {
  return (
    <div className="flex h-16 items-center justify-between border-b border-dashed px-4">
      <Link className="flex flex-row items-center gap-2" href={"/"}>
        <Image src="/official/logo.png" alt="logo" width={32} height={32} />
        <span className="instrument-serif text-xl font-semibold">
          Orafinite
        </span>
      </Link>
      <div className="flex flex-row items-center gap-3">
        <ModeSwitcher />
        <Link href={"/login"}>
          <Button variant="secondary">
            <span>Get Started</span>
          </Button>
        </Link>
      </div>
    </div>
  );
};

export default Header;
