import Banner from "@/components/layout/landing/banner";
import Demo from "@/components/layout/landing/demo";
import Features from "@/components/layout/landing/features";
import Footer from "@/components/layout/landing/footer";
import Header from "@/components/layout/landing/header";
import Hero from "@/components/layout/landing/hero";
import OurSponser from "@/components/layout/landing/our-sponser";
import Why from "@/components/layout/landing/why";

export default function Page() {
  return (
    <main className="new-container relative border-none! sm:border-dashed!">
      <Header />
      <Hero />
      <Features />
      <Demo />
      <Why />
      <OurSponser />
      <Banner />
      <Footer />
    </main>
  );
}
