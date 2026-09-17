# Uses vcpkg_from_git (no SHA-512) because this port lives inside the very
# repository it packages, so a source-archive hash would be self-referential.
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://github.com/zymuk/VirusTotalCpp.V3.git
    REF "v${VERSION}"
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DVTAPI_BUILD_EXAMPLE=OFF
        -DVTAPI_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME "vtapi" CONFIG_PATH lib/cmake/vtapi)

vcpkg_copy_pdbs()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt")