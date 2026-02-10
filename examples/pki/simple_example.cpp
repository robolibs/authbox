#include <argu/argu.hpp>
#include <authbox.hpp>
#include <echo/echo.hpp>
#include <scan/scan.hpp>

int main(int argc, char *argv[]) {
    authbox::log_startup();

    // Variables to bind arguments to
    std::string name;
    int count = 1;
    std::vector<std::string> files;
    std::string did_uri = "did:web:example.com";

    // Build the command
    auto cmd = argu::Command("argue_basic")
                   .version("1.0.0")
                   .about("A basic example demonstrating the Argue argument parsing library")
                   .arg(argu::Arg("name").positional().help("Your name").required().value_of(name).value_name("NAME"))
                   .arg(argu::Arg("count")
                            .short_name('c')
                            .long_name("count")
                            .help("Number of times to greet")
                            .value_of(count)
                            .default_value("1")
                            .value_name("NUM"))
                   .arg(argu::Arg("files")
                            .short_name('f')
                            .long_name("file")
                            .help("Input files to process")
                            .value_of(files)
                            .takes_multiple()
                            .value_name("FILE"))
                   .arg(argu::Arg("did")
                            .long_name("did")
                            .help("Optional DID URI to validate")
                            .value_of(did_uri)
                            .default_value("did:web:example.com")
                            .value_name("DID"));

    auto result = cmd.parse(argc, argv);
    if (!result) {
        return result.exit();
    }

    for (int i = 0; i < count; ++i) {
        echo("Hello, ", name, "!");
    }

    if (!files.empty()) {
        std::cout << "\nWould process files: ";
        for (size_t i = 0; i < files.size(); ++i) {
            if (i > 0)
                echo(", ");
            echo(files[i]);
        }
        echo("\n");
    }

    auto did_res = authbox::did::parse(did_uri);
    if (!did_res.is_ok()) {
        echo::warn("Invalid DID: ", did_uri);
    } else {
        echo::info("Parsed DID method=", did_res.value().method.c_str());
    }

    return 0;
}
