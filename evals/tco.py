"""palisade/evals/tco.py: a three-year total cost model sketch."""
from pydantic import BaseModel, Field


class CostLine(BaseModel):
    name: str
    one_time_usd: float = 0.0
    monthly_usd: float = 0.0
    annual_growth: float = 0.0   # 0.20 means the monthly figure grows 20 percent per year


class SourcingOption(BaseModel):
    name: str
    lines: list[CostLine] = Field(default_factory=list)

    def by_year(self, months: int = 36) -> list[float]:
        years = [0.0] * ((months + 11) // 12)
        for line in self.lines:
            years[0] += line.one_time_usd
            for m in range(months):
                years[m // 12] += line.monthly_usd * ((1.0 + line.annual_growth) ** (m // 12))
        return years


buy = SourcingOption(name="buy point product", lines=[          # illustrative placeholders, not estimates
    CostLine(name="license (per alert + per GB)", monthly_usd=40_000, annual_growth=0.30),
    CostLine(name="professional services", one_time_usd=150_000),
    CostLine(name="vendor data lake (second copy)", monthly_usd=12_000, annual_growth=0.30),
    CostLine(name="fractional platform owner + rituals + red-team", monthly_usd=20_000),
])
assemble = SourcingOption(name="assemble around owned control plane", lines=[
    CostLine(name="frontier + self-hosted inference", monthly_usd=17_000, annual_growth=0.15),
    CostLine(name="observability + gateway + OPA + OTel + ledger infra", monthly_usd=7_500),
    CostLine(name="platform team (3 FTE) + rituals + red-team", monthly_usd=68_000),
    CostLine(name="initial build + integration", one_time_usd=250_000),
])
for opt in (buy, assemble):
    y = opt.by_year()
    print(f"{opt.name:<38} y1=${y[0]:>9,.0f} y2=${y[1]:>9,.0f} y3=${y[2]:>9,.0f} total=${sum(y):>11,.0f}")
