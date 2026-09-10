from modules.subnet.report import export_vlsm_docx

def test_vlsm_word_report_is_created(tmp_path):
    path = export_vlsm_docx(tmp_path / 'vlsm.docx', '192.168.10.0/24', [{'name':'Users','requested_hosts':100,'network':'192.168.10.0','cidr':'/25','usable_range':'192.168.10.1 – 192.168.10.126','broadcast':'192.168.10.127'}])
    assert path.exists() and path.stat().st_size > 0
