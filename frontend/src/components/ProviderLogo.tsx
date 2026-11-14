/* The cloud providers' own logos, shown on a white tile so they read the same in both themes. */

export const CLOUD_PROVIDERS = [
  { id: "aws", name: "Amazon Web Services", shortName: "AWS" },
  { id: "azure", name: "Microsoft Azure", shortName: "Azure" },
  { id: "gcp", name: "Google Cloud", shortName: "Google Cloud" },
] as const;

export const providerName = (id: string, short = false) => {
  const p = CLOUD_PROVIDERS.find((x) => x.id === id);
  return p ? (short ? p.shortName : p.name) : id.toUpperCase();
};

const SIZES = { sm: 32, md: 44, lg: 64 } as const;

/**
 * The name a person gave a cloud account, or "" when it only repeats the provider
 * and the account number (the default, e.g. "AWS 123456789012"). Pages that already
 * show the provider and the number use this to avoid saying both again.
 */
export const customAccountName = (name: string | null | undefined, identifier: string | null | undefined) => {
  const rest = (name ?? "")
    .replace(identifier ?? "", "")
    .replace(/amazon web services|microsoft azure|google cloud platform|google cloud|aws|azure|gcp|account/gi, "")
    .replace(/[\s·:#()-]+/g, "");
  return rest ? (name ?? "").trim() : "";
};

export default function ProviderLogo({ provider, size = "md" }: { provider: string; size?: keyof typeof SIZES }) {
  const box = SIZES[size];
  const inner = Math.round(box * 0.68);
  return (
    <span
      className="inline-flex shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-white dark:border-zinc-700"
      style={{ width: box, height: box }}
      role="img"
      aria-label={providerName(provider)}
    >
      {provider === "gcp" ? (
        /* Google's file is the full "Google Cloud" lockup; the tile shows its cloud mark. */
        <span className="block overflow-hidden" style={{ width: inner, height: Math.round(inner * 0.82) }}>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logos/google-cloud.svg" alt="" style={{ height: "100%", maxWidth: "none" }} />
        </span>
      ) : provider === "aws" || provider === "azure" ? (
        /* eslint-disable-next-line @next/next/no-img-element */
        <img src={`/logos/${provider}.svg`} alt="" style={{ width: inner, height: inner, objectFit: "contain" }} />
      ) : (
        <span className="text-xs font-semibold text-slate-600">{provider.slice(0, 3).toUpperCase()}</span>
      )}
    </span>
  );
}
