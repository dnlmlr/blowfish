use blowfish::Blowfish;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Blowfish key setup", |b| {
        b.iter(|| {
            let _bf = black_box(Blowfish::new(b"0123456789abcdef0123456789abcdef")).unwrap();
        })
    });

    c.bench_function("Blowfish encrypt 1M (ECB)", |b| {
        let bf = Blowfish::new(b"0123456789abcdef0123456789abcdef").unwrap();
        let mut buff = vec![0_u8; 1024 * 1024];
        b.iter(|| {
            buff.chunks_exact_mut(8).for_each(|chunk| {
                bf.encrypt_block(chunk.try_into().unwrap());
            });
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
