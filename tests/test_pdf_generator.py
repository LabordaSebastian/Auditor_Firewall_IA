from src.pdf_generator import build_pdf


def test_pdf_is_valid_and_handles_unicode(sample_report, sample_topology):
    data = build_pdf(sample_report, sample_topology)
    assert data.startswith(b"%PDF")
    assert len(data) > 3000
    assert data.rstrip().endswith(b"%%EOF")
