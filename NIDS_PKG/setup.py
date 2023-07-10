from setuptools import setup

package_name = 'NIDS_PKG'

setup(
    name=package_name,
    version='0.0.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='gmo',
    maintainer_email='da.gabrielmora@gmail.com',
    description='TODO: Package description',
    license='TODO: License declaration',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'ap_node = NIDS_PKG.ap_unified_ids_node:main',
            'master_node = NIDS_PKG.master_node_script_node:main'
        ],
    },
)
