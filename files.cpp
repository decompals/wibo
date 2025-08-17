#include "common.h"
#include "files.h"
#include "handles.h"
#include <algorithm>
#include <cstring>
#include <map>

namespace files {

	static void *stdinHandle;
	static void *stdoutHandle;
	static void *stderrHandle;

	std::filesystem::path pathFromWindows(const char *inStr) {
		// Convert to forward slashes
		std::string str = inStr;
		std::replace(str.begin(), str.end(), '\\', '/');

		// Remove "//?/" prefix
		if (str.rfind("//?/", 0) == 0) {
			str.erase(0, 4);
		}

		// Remove the drive letter
		if (str.rfind("z:/", 0) == 0 || str.rfind("Z:/", 0) == 0) {
			str.erase(0, 2);
		}

		// Return as-is if it exists, else traverse the filesystem looking for
		// a path that matches case insensitively
		std::filesystem::path path = std::filesystem::path(str).lexically_normal();
		if (std::filesystem::exists(path)) {
			return path;
		}

		std::filesystem::path newPath = ".";
		bool followingExisting = true;
		for (const auto& component : path) {
			std::filesystem::path newPath2 = newPath / component;
			if (followingExisting && !std::filesystem::exists(newPath2) && (component != ".." && component != "." && component != "")) {
				followingExisting = false;
				try {
					for (std::filesystem::path entry : std::filesystem::directory_iterator{newPath}) {
						if (strcasecmp(entry.filename().c_str(), component.c_str()) == 0) {
							followingExisting = true;
							newPath2 = entry;
							break;
						}
					}
				} catch (const std::filesystem::filesystem_error&) {
					// not a directory
				}
			}
			newPath = newPath2;
		}
		if (followingExisting) {
			DEBUG_LOG("Resolved case-insensitive path: %s\n", newPath.c_str());
		} else {
			DEBUG_LOG("Failed to resolve path: %s\n", newPath.c_str());
		}

		return newPath;
	}

	std::string pathToWindows(const std::filesystem::path &path) {
		std::string str = path.lexically_normal();

		if (path.is_absolute()) {
			str.insert(0, "Z:");
		}

		std::replace(str.begin(), str.end(), '/', '\\');
		return str;
	}

	FILE *fpFromHandle(void *handle, bool pop) {
		handles::Data data = handles::dataFromHandle(handle, pop);
		if (data.type == handles::TYPE_FILE) {
			return (FILE*)data.ptr;
		} else if (data.type == handles::TYPE_UNUSED && pop) {
			return 0;
		} else {
			printf("Invalid file handle %p\n", handle);
			assert(0);
		}
	}

	/**
	 * Finds name in $PATH using standard unix rules for exec(3), but also allow
	 * files in the current working directory, regardless of it's presence in
	 * $PATH. The named file does not need to be executable.
     *
     * @param progname the name of the program
     * @return the path of the program in the current environment or working directory
     */
	std::string which(const std::string &progname) {
		// if there is are multiple path components, treat this as the path and ignore $PATH
		if (progname.find('/') == std::string::npos) {
			const char* p = getenv("PATH");

			size_t pathsize = strlen(p) + 1;
			char* path = (char*) malloc(pathsize);
			std::shared_ptr<void> defer(nullptr, [path](...){ free(path); });
			strncpy(path, p, pathsize);

			while ((p = strsep(&path, ":")) != nullptr) {
				if (*p == '\0') {
					p = ".";
				}
				std::string candidate = std::string(p) + "/" + progname;
				if (std::filesystem::exists(candidate)) {
					return std::filesystem::canonical(candidate);
				}
			}
		}

		// the original resolution behavior did not use the canonical
		// path. in most cases this shouldn't matter, but just in
		// case it does, we retain same in the default case.
		return std::filesystem::absolute(progname);
	}

	void *allocFpHandle(FILE *fp) {
		return handles::allocDataHandle(handles::Data{handles::TYPE_FILE, fp, 0});
	}

	void *getStdHandle(uint32_t nStdHandle) {
		switch (nStdHandle) {
			case ((uint32_t) -10): // STD_INPUT_HANDLE
				return stdinHandle;
			case ((uint32_t) -11): // STD_OUTPUT_HANDLE
				return stdoutHandle;
			case ((uint32_t) -12): // STD_ERROR_HANDLE
				return stderrHandle;
			default:
				return (void *) 0xFFFFFFFF;
		}
	}

	unsigned int setStdHandle(uint32_t nStdHandle, void *hHandle) {
		switch (nStdHandle) {
			case ((uint32_t) -10): // STD_INPUT_HANDLE
				stdinHandle = hHandle;
				break;
			case ((uint32_t) -11): // STD_OUTPUT_HANDLE
				stdoutHandle = hHandle;
				break;
			case ((uint32_t) -12): // STD_ERROR_HANDLE
				stderrHandle = hHandle;
				break;
			default:
				return 0; // fail
		}
		return 1; // success
	}

	void init() {
		stdinHandle = allocFpHandle(stdin);
		stdoutHandle = allocFpHandle(stdout);
		stderrHandle = allocFpHandle(stderr);
	}
}
