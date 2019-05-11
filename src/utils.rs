pub(crate) fn padding_string(input_size: usize, block_size: usize) -> String {
    let block_size_ = block_size - 1;
    let padding_len = block_size_ - ((input_size + block_size_) & block_size_);
    String::from_utf8(vec![b'X'; padding_len]).unwrap()
}