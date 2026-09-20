fn main() {
    slint_build::compile("ui/mainwindow.slint").expect("Failed to compile Slint UI definition");

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        let _ = res.compile();
    }
}
