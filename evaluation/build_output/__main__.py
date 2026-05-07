"""CLI entry point for build_output.

Usage:
    python -m evaluation.build_output frash [robustness|xo_sensitivity|xc_sensitivity|compilation_sensitivity|efficiency|dataset|isa_breakdown|all]
    python -m evaluation.build_output similarity ranking [recall_curves|mrr_table|all]
    python -m evaluation.build_output similarity equivalence [auc_table|ablation|all]
    python -m evaluation.build_output similarity [all]
    python -m evaluation.build_output all
"""
import argparse
import sys


def _run_frash(verb: str) -> None:
    if verb in ("efficiency", "all"):
        from evaluation.build_output.frash.efficiency import build_efficiency_table
        print("\n--- frash: efficiency ---")
        build_efficiency_table()
    if verb in ("dataset", "all"):
        from evaluation.build_output.frash.dataset import main as _ds
        print("\n--- frash: dataset ---")
        _ds()


def _run_similarity_ranking(verb: str) -> None:
    if verb in ("recall_curves", "all"):
        from evaluation.build_output.similarity.ranking.recall_curves import build_recall_curves
        print("\n--- similarity ranking: recall_curves ---")
        build_recall_curves()
    if verb in ("mrr_table", "all"):
        from evaluation.build_output.similarity.ranking.mrr_table import build_mrr_table
        print("\n--- similarity ranking: mrr_table ---")
        build_mrr_table()


def _run_similarity_equivalence(verb: str) -> None:
    if verb in ("auc_table", "all"):
        from evaluation.build_output.similarity.equivalence.auc_table import build_auc_table
        print("\n--- similarity equivalence: auc_table ---")
        build_auc_table()
    if verb in ("ablation", "all"):
        from evaluation.build_output.similarity.equivalence.ablation import build_ablation_plots
        print("\n--- similarity equivalence: ablation ---")
        build_ablation_plots()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.build_output",
        description="Generate paper build outputs (plots, tables, data CSVs).",
    )
    sub = parser.add_subparsers(dest="domain", metavar="DOMAIN")

    # --- frash ---
    p_frash = sub.add_parser("frash", help="FRASH-BF outputs")
    p_frash.add_argument(
        "verb",
        nargs="?",
        default="all",
        choices=["robustness", "compilation_sensitivity", "efficiency", "dataset", "isa_breakdown", "all"],
        metavar="VERB",
        help="Which output to build (default: all)",
    )

    # --- similarity ---
    p_sim = sub.add_parser("similarity", help="Similarity experiment outputs")
    sim_sub = p_sim.add_subparsers(dest="sub", metavar="SUB")

    p_rank = sim_sub.add_parser("ranking", help="1vN ranking outputs")
    p_rank.add_argument(
        "verb",
        nargs="?",
        default="all",
        choices=["recall_curves", "mrr_table", "all"],
        metavar="VERB",
        help="Which output to build (default: all)",
    )

    p_equiv = sim_sub.add_parser("equivalence", help="1v1 equivalence outputs")
    p_equiv.add_argument(
        "verb",
        nargs="?",
        default="all",
        choices=["auc_table", "ablation", "all"],
        metavar="VERB",
        help="Which output to build (default: all)",
    )

    # --- all ---
    sub.add_parser("all", help="Build every output")

    args = parser.parse_args()

    if args.domain is None:
        parser.print_help()
        sys.exit(0)

    if args.domain == "all":
        _run_frash("all")
        _run_similarity_ranking("all")
        _run_similarity_equivalence("all")
        return

    if args.domain == "frash":
        _run_frash(args.verb)
        return

    if args.domain == "similarity":
        if not args.sub:
            _run_similarity_ranking("all")
            _run_similarity_equivalence("all")
            return
        if args.sub == "ranking":
            _run_similarity_ranking(args.verb)
        elif args.sub == "equivalence":
            _run_similarity_equivalence(args.verb)


if __name__ == "__main__":
    main()
