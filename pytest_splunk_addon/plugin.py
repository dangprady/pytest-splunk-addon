# -*- coding: utf-8 -*-

import logging
import os
import pytest
import requests
from splunk_appinspect import App

from .helmut.manager.jobs import Jobs
from .helmut.splunk.cloud import CloudSplunk
from .helmut_lib.SearchUtil import SearchUtil

logger = logging.getLogger()


def pytest_addoption(parser):
    group = parser.getgroup('splunk-addon')

    group.addoption(
        '--splunk_app',
        action='store',
        dest='splunk_app',
        default='package',
        help='Path to Splunk app'
    )
    group.addoption(
        '--splunk_type',
        action='store',
        dest='splunk_type',
        default='external',
        help='Type of Splunk'
    )
    group.addoption(
        '--splunk_host',
        action='store',
        dest='splunk_host',
        default='127.0.0.1',
        help='Address of the Splunk Server'
    )
    group.addoption(
        '--splunk_port',
        action='store',
        dest='splunk_port',
        default='8089',
        help='Splunk rest port'
    )
    group.addoption(
        '--splunk_user',
        action='store',
        dest='splunk_user',
        default='admin',
        help='Splunk login user'
    )
    group.addoption(
        '--splunk_password',
        action='store',
        dest='splunk_password',
        default='changeme',
        help='Splunk password'
    )
    group.addoption(
        '--splunk_version',
        action='store',
        dest='splunk_version',
        default='latest',
        help='Splunk password'
    )

def is_responsive(url):
    try:
        response = requests.get(url)
        if response.status_code != 500:
            return True
    except ConnectionError:
        return False


def is_responsive_splunk(splunk):
    try:
        cs = CloudSplunk(splunkd_host=splunk['host'],
                         splunkd_port=splunk['port'],
                         username=splunk['username'],
                         password=splunk['password']
                         )

        conn = cs.create_logged_in_connector()
        jobs = Jobs(conn)
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def splunk(request):
    if request.config.getoption('splunk_type') == 'external':
        request.fixturenames.append('splunk_external')
        splunk = request.getfixturevalue("splunk_external")
    elif request.config.getoption('splunk_type') == 'docker':
        os.environ['splunk_version'] = request.config.getoption('splunk_version')
        request.fixturenames.append('splunk_docker')
        splunk = request.getfixturevalue("splunk_docker")
    else:
        raise Exception

    yield splunk


@pytest.fixture(scope="session")
def splunk_docker(request, docker_services, docker_ip):
    port = docker_services.port_for("splunk", 8089)

    splunk = {
        'host': docker_ip,
        'port': port,
        'username': request.config.getoption('splunk_user'),
        'password': request.config.getoption('splunk_password'),
    }

    docker_services.wait_until_responsive(
        timeout=180.0, pause=0.5, check=lambda: is_responsive_splunk(splunk)
    )

    return splunk


@pytest.fixture(scope="session")
def splunk_external(request):
    splunk = {
        'host': request.config.getoption('splunk_host'),
        'port': request.config.getoption('splunk_port'),
        'username': request.config.getoption('splunk_user'),
        'password': request.config.getoption('splunk_password'),
    }
    return splunk


@pytest.fixture(scope="session")
def splunk_search_util(splunk):
    cs = CloudSplunk(splunkd_host=splunk['host'],
                     splunkd_port=splunk['port'],
                     username=splunk['username'],
                     password=splunk['password']
                     )

    conn = cs.create_logged_in_connector()
    jobs = Jobs(conn)

    return SearchUtil(jobs, logger)


def pytest_generate_tests(metafunc):
    for fixture in metafunc.fixturenames:
        if fixture.startswith('splunk_app'):
            # Load associated test data
            tests = load_splunk_tests(metafunc.config.getoption('splunk_app'), fixture)
            if tests:
                metafunc.parametrize(fixture, tests)


def load_splunk_tests(splunk_app_path, fixture):
    app = App(splunk_app_path, python_analyzer_enable=False)
    props = app.props_conf()
    if fixture.endswith('props'):
        yield load_splunk_props(props)
    else:
        yield None


def load_splunk_props(props):
    for p in props.sects:
        if p.startswith('host::'):
            continue
        elif p.startswith('source::'):
            continue
        else:
            return return_props_param(p, p)


def return_props_param(id, value):
    return pytest.param({'field': 'sourcetype', 'value': value},
                        id=id
                        )

    # Tests are to be found in the variable `tests` of the module
    # for test in tests_module.tests.iteritems():
    #     yield test
    # if "sourcetypes" in metafunc.fixturenames or "eventtypes" in metafunc.fixturenames or "prop_elements" in metafunc.fixturenames:
    #
    #     app = App(location=metafunc.config.getoption('splunk_app'), python_analyzer_enable=False)
    #     props = app.props_conf()
    #     eventtypes = app.eventtypes_conf().sects
    #     transforms = app.transforms_conf().sects
    #
    #     if "sourcetypes" in metafunc.fixturenames:
    #
    #         params = []
    #         # Add source types which are not RENAME host:: or used to set source:: used to set SOURCETYPE
    #         for section in props.sects:
    #             if section.startswith('source::'):
    #                 if props.sects[section].options['sourcetype']:
    #                     continue
    #                 else:
    #                     params.append(
    #                         pytest.param({'sourcetype': section, 'sourcetype': section},
    #                                      marks=pytest.mark.dependency(
    #                                          name='splunk::addon::sourcetype[{}]'.format(section)
    #                                          ),
    #                                      id=section
    #                                      )
    #                     )
    #             elif section.startswith('host::'):
    #                 continue
    #             else:
    #                 params.append(
    #                     pytest.param({'sourcetype': section, 'sourcetype': section},
    #                                  marks=pytest.mark.dependency(
    #                                      name='splunk::addon::sourcetype[{}]'.format(section)
    #                                  ),
    #                                  id=section
    #                                  )
    #                 )
    #
    #
    #
    #         metafunc.parametrize("sourcetypes", params)
    #
    #     # elif "eventtypes" in metafunc.fixturenames:
    #     #     metafunc.parametrize("eventtypes", eventtypes)
    #     #
    #     # elif "prop_elements" in metafunc.fixturenames:
    #     #     extract_regex = r'\(\?\<(?P<FIELD>[^\>]+)\>'
    #     #     field_alias_regex = r'(?P<FIELD>\"[^\"]+\"|[^ ]+) * AS'
    #     #
    #     #     params = []
    #     #     for section in props.sects:
    #     #         stanza = props.sects[section]
    #     #         for name, option in stanza.options.items():
    #     #
    #     #             # Identify any fields created via an EXTRACT regex
    #     #             if name.startswith("EXTRACT-"):
    #     #                 matches = re.findall(extract_regex, option.value)
    #     #                 if matches:
    #     #                     terms = []
    #     #                     for m in matches:
    #     #                         terms.append('({}=* AND NOT {}="-" AND NOT {}="")'.format(m, m, m))
    #     #
    #     #                     condition = '( {} )'.format(' AND '.join(terms))
    #     #                     params.append(
    #     #                         pytest.param({'sourcetype': section, 'field': condition},
    #     #                                      marks=pytest.mark.dependency(
    #     #                                          depends=['splunk::addon::sourcetype[{}]'.format(section)]
    #     #                                      ),
    #     #                                      id="{}::{}".format(section, name)
    #     #                                      )
    #     #                     )
    #     #             elif name.startswith("REPORT-"):
    #     #                 used_transforms = option.value.split(",")
    #     #                 for transform in used_transforms:
    #     #                     if transform in transforms:
    #     #                         current_transform = transforms[transform]
    #     #                         matches = re.findall(extract_regex, current_transform.options['REGEX'].value)
    #     #
    #     #                         if matches:
    #     #                             terms = []
    #     #                             for m in matches:
    #     #                                 terms.append('({}=* AND NOT {}="-" AND NOT {}="")'.format(m, m, m))
    #     #
    #     #                             condition = '( {} )'.format(' AND '.join(terms))
    #     #
    #     #                             params.append(
    #     #                                 pytest.param(
    #     #                                     {'sourcetype': section, 'field': condition},
    #     #                                     marks=pytest.mark.dependency(
    #     #                                         depends=['splunk::addon::sourcetype[{}]'.format(section)]
    #     #                                     ),
    #     #                                     id="{}::{}".format(section, name)
    #     #                                     )
    #     #                             )
    #     #             elif name.startswith("FIELDALIAS-"):
    #     #                 # Identify any fields created via an EXTRACT regex
    #     #
    #     #                 matches = re.findall(field_alias_regex, option.value, re.IGNORECASE)
    #     #                 if matches:
    #     #                     term = '({}=* AND NOT {}="-" AND NOT {}="")'.format(matches[0], matches[0], matches[0])
    #     #
    #     #                     params.append(
    #     #                         pytest.param({'sourcetype': section, 'field': term },
    #     #                                      marks=pytest.mark.dependency(
    #     #                                          depends=['splunk::addon::sourcetype[{}]'.format(section)]
    #     #                                      ),
    #     #                                      id="{}::{}".format(section, name)
    #     #                                      )
    #     #                     )
    #     #             elif name.startswith("EVAL-"):
    #     #                 # Eval tests are hard we simple check to see if the field will ever populate for the source type
    #     #                 # When if or coalesce is used we should demand a manual test creation to test the paths
    #     #
    #     #                 matches = re.findall(r'EVAL-(?P<FIELD>.*)', option.name, re.IGNORECASE)
    #     #                 if matches:
    #     #                     terms = []
    #     #                     for m in matches:
    #     #                         terms.append('({}=* AND NOT {}="-" AND NOT {}="")'.format(m, m, m))
    #     #
    #     #                     condition = '( {} )'.format(' AND '.join(terms))
    #     #
    #     #                 params.append(
    #     #                     pytest.param({'sourcetype': section, 'field': condition},
    #     #                                  marks=pytest.mark.dependency(
    #     #                                      depends=['splunk::addon::sourcetype[{}]'.format(section)]
    #     #                                  ),
    #     #                                  id="{}::{}".format(section, name)
    #     #                                  )
    #     #                 )
    #     #             elif name.startswith("LOOKUP-"):
    #     #                 lookup_key_group = re.match(r'[^ ]+ +(?P<KEYS>.+) +OUTPUT', option.value, re.IGNORECASE).group('KEYS')
    #     #
    #     #                 lookup_keys = r'(?:[^ ]* +AS +)?(?P<FIELD>[^ ]+)'
    #     #
    #     #                 matches = re.findall(lookup_keys, lookup_key_group, re.IGNORECASE)
    #     #
    #     #                 if matches:
    #     #                     terms = []
    #     #                     for m in matches:
    #     #                         terms.append('({}=* AND NOT {}="-" AND NOT {}="")'.format(m, m, m))
    #     #
    #     #                     condition = '( {} )'.format(' AND '.join(terms))
    #     #
    #     #                     params.append(
    #     #                         pytest.param({'sourcetype': section, 'field': condition},
    #     #                                      marks=pytest.mark.dependency(
    #     #                                          depends=['splunk::addon::sourcetype[{}]'.format(section)]
    #     #                                      ),
    #     #                                      id="{}::{}".format(section, name)
    #     #                                      )
    #     #                     )
    #
    #         metafunc.parametrize("prop_elements", params)
