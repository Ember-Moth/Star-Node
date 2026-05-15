use std::sync::OnceLock;

static NUM_THREADS: OnceLock<usize> = OnceLock::new();

pub fn set_num_threads(num_threads: usize) {
    let _ = NUM_THREADS.set(num_threads);
}

pub fn try_set_num_threads(num_threads: usize) -> Result<(), usize> {
    NUM_THREADS.set(num_threads)
}

pub fn get_num_threads() -> usize {
    *NUM_THREADS.get_or_init(default_num_threads)
}

fn default_num_threads() -> usize {
    std::cmp::max(
        2,
        std::thread::available_parallelism()
            .map(|threads| threads.get())
            .unwrap_or(1),
    )
}
