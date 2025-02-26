import Navbar from "@/components/navbar";
import Link from "next/link";
import Image from "next/image";

export default function Homepage() {
  return (
    <section>
      <Navbar />

      {/* Home page CTA section */}
      <div className="hero-cta px-10 py-10 mt-10 flex items-start justify-between">
        <div className="w-[492px] h-[223px] text-stone-900 text-[32px] font-semibold font-Manrope uppercase leading-[52px] tracking-[2.56px]">
          Indulge in the finest flavors of India with our exquisite royal
          cuisine.{" "}
        </div>
        <div className="w-[450px] text-stone-900 text-base font-normal font-['Manrope'] capitalize leading-9 tracking-wider">
          From the kitchens of Maharajas to your plate, every dish is crafted
          with rich heritage, authentic spices, and the finest ingredients to
          give you a truly regal experience.
        </div>
        <div className="flex ">
          <div className="relative flex">
            <Link className="  " href="/menu">
              <Image
                src="/images/side-text.svg"
                alt="side"
                width={0}
                height={0}
                sizes="100vw"
                style={{ width: "40px", height: "auto" }}
              ></Image>
            </Link>
          </div>
          <Image
            src="/images/arrow.svg"
            alt="arrow"
            width={10}
            height={240}
          ></Image>
        </div>
      </div>
      {/* Home page image section */}
      <div className="mt-20">
        <Image
          src="/images/main-image.png"
          alt="home-page-image"
          width={1920}
          height={800}
        />
      </div>
    </section>
  );
}
