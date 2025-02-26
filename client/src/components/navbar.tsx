import Image from "next/image";
import Link from "next/link";

interface NavLink {
  label: string;
  href: string;
}

const navLinks: NavLink[] = [
  { label: "Home", href: "/" },
  { label: "Menu", href: "/menu" },
  { label: "Reservation", href: "/reservation" },
  { label: "About", href: "/about" },
  { label: "Contact us", href: "/contact" },
];

export default function Navbar() {
  return (
    <section className="px-10 py-10 flex flex-col gap-10">
      <div className="image-container">
        <Image
          src="/images/text.svg"
          alt="text"
          width={0}
          height={0}
          sizes="100vw"
          style={{ width: "100%", height: "auto" }}
        />
      </div>

      <div className="navbar-container font-Manrope flex w-full items-center justify-between">
        <nav className="navbar text-sm flex gap-10">
          {navLinks.map((link, index) => (
            <Link
              key={index}
              href={link.href}
              className="text-text hover:text-text-heading"
            >
              {link.label}
            </Link>
          ))}
        </nav>
        <div className="contact-container text-sm">
          <p className="flex gap-20">
            En/No <span>91+ 84818 48484</span>
          </p>
        </div>
      </div>
    </section>
  );
}
