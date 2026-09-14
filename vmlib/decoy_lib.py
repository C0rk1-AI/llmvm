"""Decoy narrative library: per-build random metadata misdirection.

Attacks the "anchor on familiar metadata" LLM failure mode with VARIETY:
a single fixed narrative (UPX+JPEG) is a fingerprint an analyst learns once.
Each build instead draws a fresh, mostly-coherent story from ~16 themes
(packers, codecs, databases, games, network, crypto, installers, fonts, ...),
each contributing section-name schemes, export-name pools, banner strings,
PDB paths, build-log lines and binary file-format fragments (~130 misleading
key strings total, further randomized via {v3}/{v4}/{yr}/{hex8}/{dom}
templates), so no two builds share a static signature.

Pure stdlib. select(rng) is deterministic given the master build rng.
"""
import random  # noqa: F401  (docs: callers pass random.Random)

M = '{v3}'   # x.y.z
V4 = '{v4}'  # x.y.z.w
YR = '{yr}'  # 1998-2025
H8 = '{hex8}'  # 8 hex digits
DOM = '{dom}'  # short domain word

# dec_* functions available for export aliasing (see gen_c.gen_decoys)
DEC_NAMES = ['dec_bmp_probe', 'dec_rle_scan', 'dec_jpeg_idct', 'dec_huff_walk',
             'dec_md5_mix', 'dec_quant_check', 'dec_png_crc']


class Theme:
    def __init__(self, tid, kind, sections, banner, exports, strings,
                 frags, pdbs):
        self.id = tid
        self.kind = kind
        self.sections = sections      # {orig: new8char}
        self.banner = banner          # [bytes] banner-ish blocks
        self.exports = exports        # [str] candidate export aliases (>=7)
        self.strings = strings        # [bytes] misc strings (templated)
        self.frags = frags            # [bytes] binary file-format fragments
        self.pdbs = pdbs              # [bytes] pdb path templates


UPX_SECS = {'.text': 'UPX1', '.rdata': 'UPX2', '.data': 'UPX0', '.rsrc': 'UPX3',
            '.reloc': 'UPX4', '.idata': 'UPX5', '.pdata': 'UPX6', '.bss': 'UPX7'}

THEMES = [
    Theme('upx_classic', 'packer', UPX_SECS,
          [b'UPX!\r\n'
           b'$Info: This file is packed with the UPX executable packer http://upx.sf.net $\r\n'
           b'$Id: UPX ' + M.encode() + b' Copyright (C) 1996-' + YR.encode() + b' the UPX Team. All Rights Reserved. $\r\n'
           b'UPX ' + M.encode() + b' (with modifications)\r\n'],
          ['jpeg_dct_quant', 'jpeg_huff_decode', 'jpeg_idct_8x8',
           'png_crc32_table', 'bmp_rle_probe', 'md5_fingerprint'],
          [b'JpegLite.dll v' + M.encode() + b' (static)\x00',
           b'imgcodec_merge.bat --profile release /LTCG /GL\x00',
           b'quant_huff_tables.obj idct_scalar.obj idct_sse2.obj\x00',
           b'http://www.' + DOM.encode() + b'codec.org/spec/jpeg-'.replace(b'jpeg-', b'') + b'baseline.htm\x00'],
          [b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
           b'\xff\xdb\x00CJpegLite quant table - baseline series 0x2C'
           b'\xff\xc0\x00\x11\x08\x00\x40\x00\x40\x03\x01!\x00\x02\x11\x01\x03\x11\x01'
           b'\xff\xc4\x1fJpegLite huffman DC/AC tables (optimized)\xff\xda\x00\x0c\xff\xd9',
           b'BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00'
           b'\x40\x00\x00\x00\x40\x00\x00\x00\x01\x00\x18\x00\x00\x00'
           b'JpegLite BMP fallback frame buffer\r\n'],
          [b'C:\\src\\imgcodec\\JpegLite\\Release\\JpegLite.pdb\x00',
           b'C:\\src\\imgcodec\\JpegLite\\obj\\release\\' + DOM.encode() + b'.pdb\x00']),

    Theme('aspack', 'packer',
          {'.text': '.aspack', '.rdata': '.adata', '.data': '.aspack2',
           '.rsrc': '.aspack3', '.reloc': '.rsrc', '.idata': '.idata',
           '.pdata': '.aspack4', '.bss': '.aspack5'},
          [b'aPa\r\nASPack ' + M.encode() + b' - trial version build ' + YR.encode() + b'\r\n'],
          ['aspk_decomp_block', 'aspk_import_fix', 'aspk_reloc_merge',
           'aspk_crc_check', 'lzx_decode_frame', 'huff_canon_build'],
          [b'ASPack(b) ' + M.encode() + b' registered to ' + DOM.encode() + b' software ltd.\x00',
           b'pe_sections_compact() -> ' + H8.encode() + b' bytes saved\x00',
           b'import_thunk_rebuild: %d entries, iat_mask=' + H8.encode() + b'\x00'],
          [b'\x60\xe8\x00\x00\x00\x00]AsPack! seal section marker\x00',
           b'LZX window 32KB huffman canon table probe\x00'],
          [b'C:\\Program Files\\ASPack\\projects\\' + DOM.encode() + b'\\release.pdb\x00']),

    Theme('vmprotect', 'protector',
          {'.text': '.vmp0', '.rdata': '.vmp1', '.data': '.vmp2',
           '.rsrc': '.vmp3', '.reloc': '.vmp4', '.idata': '.idata',
           '.pdata': '.vmp5', '.bss': '.vmp6'},
          [b'VMProtect ' + M.encode() + b' ultra (mutation+virtualization)\r\n'],
          ['vmp_mutate_seg', 'vmp_vm_entry', 'vmp_handle_table',
           'vmp_reg_context', 'lic_key_decode', 'sdk_decrypt_string'],
          [b'.vmp0 markers: virtualized ' + H8.encode() + b' / mutated ' + H8.encode() + b' bytes\x00',
           b'VMProtectSDKBegin("license_check") EndMarker ' + H8.encode() + b'\x00',
           b'handler count: 224, decode key mask 0x' + H8.encode() + b'\x00'],
          [b'\x56\x4d\x50\x72\x6f\x74\x65\x63\x74 VMP2 stamped tag\x00'],
          [b'C:\\src\\prot\\' + DOM.encode() + b'_guard\\Release\\vmsec.pdb\x00']),

    Theme('themida', 'protector',
          {'.text': 'TMD0', '.rdata': 'TMD1', '.data': 'TMD2', '.rsrc': 'TMD3',
           '.reloc': 'TMD4', '.idata': '.idata', '.pdata': 'TMD5',
           '.bss': 'TMD6'},
          [b'Themida/WinLicense ' + M.encode() + b' - Advanced Markers SE\r\n'],
          ['tmd_api_wrap', 'tmd_crypto_box', 'tmd_cpu_fingerprint',
           'wl_license_probe', 'tmd_anti_dump', 'sdk_is_registered'],
          [b'WinLicense SDK ' + M.encode() + b' - OEM license: ' + H8.encode() + b'-' + H8.encode() + b'\x00',
           b'anti-debug layers: 7, ring3 detour scan enabled\x00'],
          [b'\x53\x45\x43\x55\x52\x45 WinLicense tag fragment\x00'],
          [b'C:\\src\\license\\themida_'.replace(b'themida_', b'wl_') + DOM.encode() + b'\\x64\\Release\\wlcore.pdb\x00']),

    Theme('enigma', 'protector',
          {'.text': '.enigma1', '.rdata': '.enigma2', '.data': '.enigma3',
           '.rsrc': '.enigma4', '.reloc': '.reloc2', '.idata': '.idata',
           '.pdata': '.enigma5', '.bss': '.enigma6'},
          [b'Enigma Protector ' + M.encode() + b' x64 - Demo limitations apply\r\n'],
          ['eng_vm_step', 'eng_box_decode', 'eng_checksum_rt',
           'eng_res_crypt', 'eng_reg_key', 'eng_hwid_hash'],
          [b'Enigma box: %d sections packed, decoder stub ' + H8.encode() + b'\x00',
           b'registration: name hash ' + H8.encode() + b' hwid ' + H8.encode() + b'\x00'],
          [b'\x1f\x8b\x08\x00gzip2 inner resource container probe\x00'],
          [b'C:\\src\\guard\\enigma\\' + DOM.encode() + b'\\Release\\engbox.pdb\x00']),

    Theme('nsis', 'installer',
          {'.text': '.ndata', '.rdata': '.ndata2', '.data': '.ndata3',
           '.rsrc': '.ndata4', '.reloc': '.ndata5', '.idata': '.idata',
           '.pdata': '.ndata6', '.bss': '.ndata7'},
          [b'Nullsoft Install System v' + M.encode() + b'\r\n'],
          ['nsis_plugin_call', 'lzma_decode_solid', 'crc32_block',
           'file_get_offset', 'ns_exec_spawn', 'log_set_cmd'],
          [b'Nullsoft.NSIS.exe /S /D=%s silent profile ' + H8.encode() + b'\x00',
           b'LZMA solid block: dict 16MB, lc=3 lp=0 pb=2\x00',
           b'install log: [%s] wrote %d bytes, crc ' + H8.encode() + b'\x00'],
          [b'PK\x03\x04\x14\x00\x00\x00\x08\x00inner payload zip local header\x00'],
          [b'C:\\build\\nsis\\' + DOM.encode() + b'\\setup\\Release\\setup.pdb\x00']),

    Theme('sqlite', 'database',
          {'.text': 'SQLC', '.rdata': 'SQLR', '.data': 'SQLD', '.rsrc': 'SQLS',
           '.reloc': 'SQLX', '.idata': '.idata', '.pdata': 'SQLP',
           '.bss': 'SQLB'},
          [b'SQLite format 3\x00library ' + M.encode() + b' compile opts: ENABLE_FTS5\r\n'],
          ['sqlite3_ckpt_step', 'sqlite3_vtab_probe', 'sqlite3_wal_frame',
           'sqlite3_backup_one', 'sqlite3_busy_eval', 'btree_init_page'],
          [b'SQLite ' + M.encode() + b' ' + YR.encode() + b'-' + H8.encode() + b'\x00',
           b'PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;\x00',
           b'SELECT count(*) FROM sqlite_master WHERE type=\'index\';\x00',
           b'btree.c: initPage() hdr offset %d cell %d\x00'],
          [b'SQLite format 3\x00'
           b'\x10\x00\x01\x01\x00@ \x20\x00\x00\x00\x00'
           b'\xd6\x00\x00\x00' + H8.encode() + b'\x00\x00\x00\x00'],
          [b'C:\\src\\sqlite\\shell\\Release_x64\\sqlite_shell.pdb\x00',
           b'C:\\work\\db\\' + DOM.encode() + b'tool\\Release\\dbmgr.pdb\x00']),

    Theme('zlib', 'compressor',
          {'.text': 'DEFL', '.rdata': 'INFL', '.data': 'ZIPD', '.rsrc': 'ZIPR',
           '.reloc': 'ZIPX', '.idata': '.idata', '.pdata': 'ZIPP',
           '.bss': 'ZIPB'},
          [b' deflate 1.' + M.encode() + b' Copyright ' + YR.encode() + b' Jean-loup Gailly\r\n'],
          ['deflateInit2_', 'inflateInit2_', 'crc32_combine', 'adler32_simd_',
           'zlib_version', 'gzclose_r'],
          [b' inflate 1.' + M.encode() + b' Copyright ' + YR.encode() + b' Mark Adler\x00',
           b'zlib version ' + M.encode() + b', flags 0x' + H8.encode() + b'\x00',
           b'deflateInit2_: level 6 windowBits 15 memLevel 8 strategy 0\x00'],
          [b'\x1f\x8b\x08\x00' + H8.encode() + b'\x00\x03gzip member header probe\x00',
           b'\x78\x9c\x00\x00zlib stream default compression header\x00',
           b'PK\x05\x06\x00\x00\x00\x00zip end-of-central-dir probe\x00'],
          [b'C:\\src\\zlib-' + M.encode().replace(b'.', b'') + b'\\contrib\\minizip\\Release\\minizip.pdb\x00']),

    Theme('libpng', 'codec',
          {'.text': 'PNGC', '.rdata': 'PNGB', '.data': 'PNGD', '.rsrc': 'PNGS',
           '.reloc': 'PNGX', '.idata': '.idata', '.pdata': 'PNGP',
           '.bss': 'PNGB2'},
          [b'libpng warning: iCCP profile chunk size %d\r\n'],
          ['png_check_chunk', 'png_read_filter_row', 'png_adam7_pass',
           'png_crc32_fin', 'png_gamma_shift', 'png_palette_idx'],
          [b'libpng version 1.' + M.encode() + b' - pnglibconf.h build ' + YR.encode() + b'\x00',
           b'PNG_CHUNK: IHDR 8x8 bit_depth=8 color_type=3\x00',
           b'tRNS palette transparency table applied\x00'],
          [b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00 \x00\x00\x00 '
           b'\x08\x03\x00\x00\x00'
           b'IDAT probe: zlib window 32K\x00'],
          [b'C:\\src\\libpng' + M.encode().replace(b'.', b'') + b'\\projects\\Release\\libpng' + M.encode().replace(b'.', b'') + b'.pdb\x00']),

    Theme('freetype', 'font',
          {'.text': 'FTTX', '.rdata': 'FTRD', '.data': 'FTDT', '.rsrc': 'FTSB',
           '.reloc': 'FTRL', '.idata': '.idata', '.pdata': 'FTPD',
           '.bss': 'FTBS'},
          [b'FreeType library: glyph raster cache ' + H8.encode() + b'\r\n'],
          ['FT_Init_FreeType2', 'ft_glyph_load_raw', 'ttf_parse_maxp',
           'otf_lookup_feat', 'cff_index_read', 'ft_bitmap_copy'],
          [b'FreeType ' + M.encode() + b' compiled ' + YR.encode() + b' with zlib+png support\x00',
           b'face->num_glyphs=%d units_per_EM=2048\x00',
           b'hinting: autohint light, subpixel AA on\x00'],
          [b'\x00\x01\x00\x00\x00\x03\x00\x60TrueType glyf table fragment probe\x00',
           b'OTTO\x00\x00cff charset probe\x00'],
          [b'C:\\src\\freetype' + M.encode().replace(b'.', b'') + b'\\objs\\x64\\Release\\freetype.pdb\x00']),

    Theme('openal_audio', 'audio',
          {'.text': 'ALCX', '.rdata': 'ALRD', '.data': 'ALDT', '.rsrc': 'ALSB',
           '.reloc': 'ALRL', '.idata': '.idata', '.pdata': 'ALPD',
           '.bss': 'ALBS'},
          [b'OpenAL Soft on WinMM\x00renderer probe ' + H8.encode() + b'\r\n'],
          ['alGenBuffers2', 'alBufferSamplesSOFT', 'alcMakeCurrent2',
           'flac_frame_seek', 'vorbis_block_decode', 'opus_map_decode'],
          [b'OpenAL Soft ' + M.encode() + b' (' + H8.encode() + b')\x00',
           b'AL_FORMAT_STEREO16 freq 44100 samples %d\x00',
           b'vorbis info: channels=2 rate=44100 bitrate nominal=112000\x00'],
          [b'RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x02\x00'
           b'\x44\xac\x00\x00\x10\xb1\x02\x00\x04\x00\x10\x00data',
           b'fLaC\x00\x00\x00\x22streaminfo block probe\x00',
           b'OpusHead\x01\x00\x01\x00\x80\xbb\x00\x00opus packet probe\x00'],
          [b'C:\\src\\audio\\' + DOM.encode() + b'mixer\\x64\\Release\\softmix.pdb\x00']),

    Theme('game_mono', 'game',
          {'.text': 'MONO', '.rdata': 'MONR', '.data': 'MOND', '.rsrc': 'MONS',
           '.reloc': 'MONX', '.idata': '.idata', '.pdata': 'MONP',
           '.bss': 'MONB'},
          [b'<Module> mono jit runtime ' + M.encode() + b'\r\n'],
          ['mono_object_new2', 'mono_runtime_invoke2', 'il2cpp_icall_probe',
           'script_gc_root', 'assetbundle_crc', 'mono_string_intern2'],
          [b'UnityPlayer.dll injected runtime ' + M.encode() + b' (IL2CPP)\x00',
           b'AssetBundle manifest: crc ' + H8.encode() + b' version ' + V4.encode() + b'\x00',
           b'mono: loaded assembly Game.' + DOM.encode().capitalize() + b'.dll (v' + M.encode() + b')\x00'],
          [b'PK\x03\x04\x14\x00\x08\x08\x08\x00assets/TextAsset.bytes\x00',
           b'\x1a\x00\x00\x00unity bundle signature UnityFS\x00'],
          [b'C:\\build\\game\\' + DOM.encode() + b'\\il2cpp\\Release\\GameAssembly.pdb\x00']),

    Theme('netclient', 'network',
          {'.text': 'NETC', '.rdata': 'NETR', '.data': 'NETD', '.rsrc': 'NETS',
           '.reloc': 'NETX', '.idata': '.idata', '.pdata': 'NETP',
           '.bss': 'NETB'},
          [b'curl/' + M.encode() + b' (Windows) libcurl/' + M.encode() + b' OpenSSL/3.' + M.encode() + b'\r\n'],
          ['curl_easy_init2', 'ws_frame_mask', 'tls13_derive_secret',
           'http_chunk_decode', 'dns_cache_probe', 'socks5_handshake2'],
          [b'User-Agent: ' + DOM.encode() + b'-client/' + M.encode() + b' (Windows NT 10.0; Win64)\x00',
           b'GET /api/v' + M.encode().replace(b'.', b'') + b'/status HTTP/1.1\r\nHost: ' + DOM.encode() + b'.api\r\n\x00',
           b'WebSocket: permessage-deflate; server ext ok, rtt %dms\x00'],
          [b'\x16\x03\x01\x00TLS 1.3 ClientHello fragment probe\x00',
           b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\x00'],
          [b'C:\\src\\net\\' + DOM.encode() + b'sync\\x64\\Release\\syncclient.pdb\x00']),

    Theme('wallet', 'crypto',
          {'.text': 'CRPX', '.rdata': 'CRPR', '.data': 'CRPD', '.rsrc': 'CRPS',
           '.reloc': 'CRPX2', '.idata': '.idata', '.pdata': 'CRPP',
           '.bss': 'CRPB'},
          [b'BIP32/BIP44 deterministic wallet core ' + M.encode() + b'\r\n'],
          ['secp256k1_ecdsa_rec', 'hd_derive_path', 'bip39_checksum_ok',
           'base58_encode_blk', 'pbkdf2_hmac_ish', 'mnemonic_index_of'],
          [b'BIP39 wordlist english: 2048 entries, checksum bits=8\x00',
           b'm/44\'/60\'/0\'/0/%d derived, fingerprint ' + H8.encode() + b'\x00',
           b'base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz\x00'],
          [b'\x04\x88\xB2\x0Expub version bytes probe (BIP32)\x00',
           b'\x80\x00\x00\x00\x00xprv hardened key probe\x00'],
          [b'C:\\src\\vault\\' + DOM.encode() + b'wallet\\Release\\walletcore.pdb\x00']),

    Theme('driver_wdf', 'driver',
          {'.text': 'INIT', '.rdata': 'RINIT', '.data': 'DINIT',
           '.rsrc': 'SINIT', '.reloc': '.reloc', '.idata': '.idata',
           '.pdata': 'PINIT', '.bss': 'BINIT'},
          [b'WDFKMDF driver framework entry probe ' + H8.encode() + b'\r\n'],
          ['wdf_io_queue_dispatch', 'kmdf_timer_dpc', 'mdl_map_locked',
           'ioctl_ctl_2380', 'reg_filter_cb', 'dma_common_buf'],
          [b'KMDF v' + M.encode() + b' - DriverEntry ok, WdfDriverCreate tag ' + H8.encode() + b'\x00',
           b'IOCTL_' + DOM.encode().upper() + b'_CTL_CODE(FILE_DEVICE_UNKNOWN, 0x%x, METHOD_BUFFERED)\x00',
           b'WPP recorder: log session ' + H8.encode() + b' enabled\x00'],
          [b'MZ\x00\x00\x00\x00inner PE resource probe\x00',
           b'\x0e\x00\x00\x00WPP_TRACE binary block\x00'],
          [b'C:\\WinDDK\\build\\' + DOM.encode() + b'sys\\x64\\Release\\' + DOM.encode() + b'sys.pdb\x00']),

    Theme('node_addon', 'runtime',
          {'.text': 'V8XX', '.rdata': 'V8RD', '.data': 'V8DT', '.rsrc': 'V8SB',
           '.reloc': 'V8RL', '.idata': '.idata', '.pdata': 'V8PD',
           '.bss': 'V8BS'},
          [b'node::Start (node.js v' + M.encode() + b') addon entry\r\n'],
          ['napi_create_object2', 'v8_isolate_scope2', 'js_callback_trampoline',
           'napi_typeof_probe', 'json_parse_native', 'promise_resolve_all2'],
          [b'node:internal/modules/cjs/loader boot ok pid %d\x00',
           b'V8 ' + M.encode() + b' heap limit 4096MB, snapshot blob ' + H8.encode() + b'\x00',
           b'napi_register_module_v1: %d exports bound\x00'],
          [b'{"name":"' + DOM.encode() + b'-addon","version":"' + M.encode() + b'","main":"index.js"}\x00',
           b'\x00\x61\x73\x6dwasmdyne module header probe\x00'],
          [b'C:\\src\\node\\' + DOM.encode() + b'addon\\build\\Release\\addon.node.pdb\x00']),

    Theme('dotnet_confuser', 'dotnet',
          {'.text': 'CNFS', '.rdata': 'CNFR', '.data': 'CNFD', '.rsrc': 'CNFS2',
           '.reloc': 'CNFX', '.idata': '.idata', '.pdata': 'CNFP',
           '.bss': 'CNFB'},
          [b'ConfuserEx ' + M.encode() + b' - anti tamper & constants protection\r\n'],
          ['cnfs_dyn_decrypt', 'cnfs_anti_tamper2', 'cnfs_res_encrypt',
           'cnfs_ctrl_flow', 'cnfs_ref_proxy', 'cnfs_anti_debug2'],
          [b'<Module>.cctor: constants decrypted ' + H8.encode() + b' entries\x00',
           b'Confuser.Core.Pipeline: pack>inject>protect done in %dms\x00',
           b'strong name: RSA ' + H8.encode() + b' public key token\x00'],
          [b'BSJBv4.0.30319#~#Strings blob heap fragment\x00'],
          [b'C:\\src\\dotnet\\' + DOM.encode() + b'app\\obj\\Release\\app.pdb\x00']),

    Theme('installer_inno', 'installer',
          {'.text': 'INNO', '.rdata': 'INNR', '.data': 'INND', '.rsrc': 'INNS',
           '.reloc': 'INNX', '.idata': '.idata', '.pdata': 'INNP',
           '.bss': 'INNB'},
          [b'Inno Setup Setup.Lzh compressor ' + M.encode() + b'\r\n'],
          ['inn_comp_lzma2', 'inn_crc_verify', 'inn_register_server',
           'inn_shell_exec2', 'inn_extract_file2', 'inn_msg_box'],
          [b'InnoSetupMessages: SetupLdr ' + M.encode() + b' (' + YR.encode() + b')\x00',
           b'[Files] Source: "release\\*.dll"; DestDir: "{app}"; Flags: ignoreversion\x00',
           b'[Registry] Root: HKLM; Subkey: "Software\\' + DOM.encode() + b'"\\\x00'],
          [b'rDlPtS02InnoSetupLdr inner setup.0 marker\x00',
           b'zlb\x1aLZMA1 compressed setup data header\x00'],
          [b'C:\\src\\setup\\inno\\' + DOM.encode() + b'\\Output\\setup.pdb\x00']),
]

_UTF16_HINTS = [b'xml version="1.0" encoding="UTF-16"?><manifest/>',
                b'ProductName', b'InternalName', b'FileDescription',
                b'LegalCopyright (C) ', b'OriginalFilename']

_JUNK = [b'/GS /guard:cf /Zi /O2 /Oi /MT precompiled header ok\x00',
         b'Signed: ' + b'0x' + H8.encode() + b', audit: ' + b'0x' + H8.encode() + b'\x00',
         b'checksum ok (' + b'0x' + H8.encode() + b') size %d\x00',
         b'(c) ' + YR.encode() + b' ' + DOM.encode().capitalize() + b' Software. All rights reserved.\x00',
         b'build agent: win2019-' + H8.encode() + b' vs2017 toolset 14.' + M.encode() + b'\x00']


def _subst(rng, b):
    """Randomize {v3}/{v4}/{yr}/{hex8}/{dom} placeholders in a bytes template."""
    def ver():
        return b'%d.%d.%d' % (rng.randrange(1, 9), rng.randrange(0, 30),
                              rng.randrange(0, 40))
    for _ in range(6):
        for tok, gen in ((M.encode(), ver),
                         (V4.encode(), lambda: ver() + b'.%d' % rng.randrange(0, 9)),
                         (YR.encode(), lambda: b'%d' % rng.randrange(1998, 2026)),
                         (H8.encode(), lambda: b'%08x' % rng.getrandbits(32)),
                         (DOM.encode(), lambda: rng.choice(
                             [b'acme', b'nova', b'aurora', b'zeta', b'pine',
                              b'quartz', b'lumen', b'orbit', b'delta', b'onyx',
                              b'vex', b'kite', b'slate', b'flux']))):
            b = b.replace(tok, gen())
    return b


class Combo:
    def __init__(self, theme_id, kind, sections, exports, jd_blob, blended,
                 dllname='libcore.dll'):
        self.theme_id = theme_id        # primary theme id
        self.kind = kind
        self.sections = sections        # {orig: new}
        self.exports = exports          # [(alias, dec_name)]
        self.jd_blob = jd_blob          # bytes for the decoy section
        self.blended = blended          # [theme ids contributing]
        self.dllname = dllname          # overwrites the PE export-dir module name


def select(rng, dec_names=None):
    """Deterministically draw a per-build narrative combo from the master rng."""
    dec_names = dec_names or DEC_NAMES
    primary = rng.choice(THEMES)
    blended = [primary.id]
    # 65%: coherent single-narrative build (strongest first-impression pull);
    # 35%: blend a secondary theme into exports/strings (dual-purpose tool look)
    secondary = rng.choice(THEMES) if rng.random() < 0.35 else None
    if secondary and secondary.id != primary.id:
        blended.append(secondary.id)

    # sections: from primary only (a coherent section scheme)
    sections = dict(primary.sections)

    # exports: 4..7 names; aliases from primary (or 50/50 with secondary)
    pool = list(primary.exports)
    if secondary:
        pool = pool + secondary.exports
    names = rng.sample(pool, min(len(pool), rng.randrange(4, 8)))
    if len(names) < 4:
        names = (names * 4)[:4]
    decs = list(dec_names)
    rng.shuffle(decs)
    exports = list(zip(names, decs[:len(names)]))

    # decoy section content: banner + pdb + frags + strings, shuffled
    parts = []
    for bb in primary.banner:
        parts.append(_subst(rng, bb))
    parts.append(_subst(rng, rng.choice(primary.pdbs)))
    for f in rng.sample(primary.frags, min(len(primary.frags),
                                           rng.randrange(1, 4))):
        parts.append(_subst(rng, f))
    strs = primary.strings + (secondary.strings if secondary else [])
    for s in rng.sample(strs, min(len(strs), rng.randrange(3, 7))):
        parts.append(_subst(rng, s))
    # generic build noise + 1-2 utf-16 anchors (show up in IDA's unicode list)
    for j in rng.sample(_JUNK, min(len(_JUNK), rng.randrange(1, 3))):
        parts.append(_subst(rng, j))
    for u in rng.sample(_UTF16_HINTS, min(len(_UTF16_HINTS),
                                          rng.randrange(1, 3))):
        parts.append(_subst(rng, u).decode('latin-1').encode('utf-16le')
                      + b'\x00\x00')
    rng.shuffle(parts)
    blob = b'\x00'.join(parts) + b'\x00'
    blob += b'\x00' * ((-len(blob)) % 16)
    # module name coherent with the export story: 'sqlite3_ckpt_step' ->
    # 'sqlite3.dll'. Replaces the linker's original output name in the
    # export directory (v3 leak closure, see pepolish.patch_export_name).
    stem = exports[0][0].split('_')[0] if exports else 'libcore'
    stem = ''.join(c for c in stem if c.isalpha()) or 'libcore'
    return Combo(primary.id, primary.kind, sections, exports, blob, blended,
                 dllname=(stem + '.dll').lower())
