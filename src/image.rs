//! Open decode of the VFS495 raw EP2 DLI stream into a grayscale image.
//!
//! Frame format (reverse-engineered, confirmed on our captures):
//!   `01 fe <seq:u16 LE> <f4> <f5> <width:u8> 00` then `<payload>` pixel bytes.
//! Frames are FIXED size: 8-byte header + `payload` pixels, delimited by `01 fe`
//! and spaced `stride` apart. The width byte is NOT the frame length — treating
//! it as one is the drift trap earlier drivers fell into.
//!
//! Column descramble for the main image is a per-line reversal (equivalently
//! `perm[i] = width-1-i`); an explicit permutation table may be supplied.
//!
//! NOTE — remaining open-decode gap: HP's full pipeline also assembles a
//! width-264 main image interleaved with width-200 navigation frames
//! (irDliRTFalconData / UnpackLineRT). That demux is not yet ported to open
//! code; this module decodes the width-200 main-frame path that our reference
//! `scripts/decode_image.py` established. See NOTES.md.

/// A decoded, unreconstructed line matrix (row-major, `f32` intensities).
pub struct Lines {
    pub data: Vec<f32>,
    pub rows: usize,
    pub cols: usize,
}

/// Extract the longest run of fixed-stride frames from a raw EP2 byte stream.
pub fn parse_frames(buf: &[u8], payload: usize, stride: usize, perm: Option<&[usize]>) -> Lines {
    // find all 01 fe markers
    let mut marks = Vec::new();
    let mut i = 0usize;
    while i + 1 < buf.len() {
        if buf[i] == 0x01 && buf[i + 1] == 0xfe {
            marks.push(i);
        }
        i += 1;
    }
    // longest contiguous run whose neighbours are exactly `stride` apart
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut run_start = 0usize;
    let mut k = 0usize;
    while k < marks.len() {
        let mut j = k;
        while j + 1 < marks.len() && marks[j + 1] - marks[j] == stride {
            j += 1;
        }
        if j - k + 1 > best_len {
            best_len = j - k + 1;
            best_start = k;
            run_start = k;
        }
        let _ = run_start;
        k = j + 1;
    }

    let mut data = Vec::new();
    let mut rows = 0usize;
    if best_len > 0 {
        for idx in best_start..best_start + best_len {
            let body = marks[idx] + 8;
            if body + payload <= buf.len() {
                for c in 0..payload {
                    let src = match perm {
                        Some(p) => p[c],
                        None => payload - 1 - c, // reverse
                    };
                    data.push(buf[body + src] as f32);
                }
                rows += 1;
            }
        }
    }
    Lines { data, rows, cols: payload }
}

/// Simple separable box blur (radius `r`) used for local normalization.
fn box_blur(src: &[f32], rows: usize, cols: usize, r: usize) -> Vec<f32> {
    let mut tmp = vec![0f32; src.len()];
    // horizontal
    for y in 0..rows {
        for x in 0..cols {
            let x0 = x.saturating_sub(r);
            let x1 = (x + r + 1).min(cols);
            let mut s = 0f32;
            for xx in x0..x1 {
                s += src[y * cols + xx];
            }
            tmp[y * cols + x] = s / (x1 - x0) as f32;
        }
    }
    // vertical
    let mut out = vec![0f32; src.len()];
    for x in 0..cols {
        for y in 0..rows {
            let y0 = y.saturating_sub(r);
            let y1 = (y + r + 1).min(rows);
            let mut s = 0f32;
            for yy in y0..y1 {
                s += tmp[yy * cols + x];
            }
            out[y * cols + x] = s / (y1 - y0) as f32;
        }
    }
    out
}

/// Local mean/contrast normalization → 8-bit ridge image.
pub fn normalize(lines: &Lines) -> Vec<u8> {
    let (rows, cols) = (lines.rows, lines.cols);
    if rows == 0 {
        return Vec::new();
    }
    // subtract per-column fixed pattern (mean over rows)
    let mut res = lines.data.clone();
    for x in 0..cols {
        let mut m = 0f32;
        for y in 0..rows {
            m += res[y * cols + x];
        }
        m /= rows as f32;
        for y in 0..rows {
            res[y * cols + x] -= m;
        }
    }
    // local contrast normalization
    let mean = box_blur(&res, rows, cols, 8);
    let mut hp = vec![0f32; res.len()];
    for i in 0..res.len() {
        hp[i] = res[i] - mean[i];
    }
    let absmap: Vec<f32> = hp.iter().map(|v| v.abs()).collect();
    let scale = box_blur(&absmap, rows, cols, 8);
    let mut out = vec![0u8; res.len()];
    for i in 0..res.len() {
        let v = hp[i] / (scale[i] + 1e-3) * 48.0 + 128.0;
        out[i] = v.clamp(0.0, 255.0) as u8;
    }
    out
}

/// Write a P5 (binary) PGM.
pub fn write_pgm(path: &str, pixels: &[u8], cols: usize, rows: usize) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    write!(f, "P5\n{cols} {rows}\n255\n")?;
    f.write_all(pixels)
}
