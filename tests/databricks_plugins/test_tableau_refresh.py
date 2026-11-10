from collections import namedtuple
from datetime import datetime

import pytest

from brickflow_plugins.operators import tableau_refresh_operator as tableau

TSC = tableau.TSC

pytestmark = pytest.mark.skipif(
    TSC is None, reason="tableauserverclient is not installed"
)


class TestTableauWrapper:
    @pytest.fixture(autouse=True, name="tableau_server")
    def tableau_server(self, mocker):
        _server = mocker.patch(
            "brickflow_plugins.operators.tableau_refresh_operator.TSC.Server"
        )
        # pylint: disable=attribute-defined-outside-init
        self.mock_server = _server.return_value

        from brickflow_plugins.operators.tableau_refresh_operator import (
            TableauWrapper,
        )

        tw = TableauWrapper(
            server="https://tableau.domain.com",
            username="user",
            password="pass",
            site="site",
        )
        # pylint: disable=attribute-defined-outside-init
        self.tableau_wrapper = tw
        self.tableau_wrapper._authenticate()

        # Mocking various returns from the Tableau server
        def create_mock_object(name_prefix: str, object_id: int):
            obj = mocker.MagicMock()
            obj.name = f"{name_prefix}-{object_id}"
            obj.project_id = f"{object_id}"
            return obj

        class Endpoint:
            """Endpoint shaped like tableauserverclient's.

            ``get`` returns real ``PaginationItem`` objects because ``TSC.Pager``
            compares page counts, and a fresh list per call because older
            ``Pager`` versions consume the list they are given. The object is
            not callable, so every ``Pager`` version pages through ``get``.
            """

            def __init__(self, items: list):
                self.items = items
                self.refresh = mocker.MagicMock()

            def get(self, *_args, **_kwargs):
                items = self.items
                return list(items), TSC.PaginationItem.from_single_page_list(items)

        # Projects
        mock_projects = []

        def create_mock_project(
            name_prefix: str,
            project_id: int,
            parent_id: int = None,
            name_override: str = None,
        ):
            mock_project = mocker.MagicMock()
            mock_project.name = (
                f"{name_prefix}-{project_id}" if not name_override else name_override
            )
            mock_project.id = (
                f"{project_id}" if not parent_id else f"{project_id * parent_id}"
            )
            mock_project.parent_id = f"{parent_id}" if parent_id else None
            return mock_project

        # Parent Projects
        for i in range(1, 3):
            mock_projects.append(
                create_mock_project(name_prefix="parent-project", project_id=i)
            )
            # Child Projects
            r = range(3, 5) if i == 1 else range(4, 6)
            for ix in r:
                mock_projects.append(
                    create_mock_project(
                        name_prefix="project", project_id=ix, parent_id=i
                    )
                )

        # Two projects with the same name: one in root (no parent_id), the other under 'parent-project-1'
        mock_projects.append(
            create_mock_project(
                name_prefix="project", project_id=100, name_override="project-foo"
            )
        )
        mock_projects.append(
            create_mock_project(
                name_prefix="project",
                project_id=101,
                name_override="project-foo",
                parent_id=1,
            )
        )

        self.mock_server.projects = Endpoint(mock_projects)

        # Data Sources
        mock_ds = create_mock_object("datasource", 1)
        mock_conn = create_mock_object("connection", 1)
        mock_conn.type = "baz"
        mock_ds.connections = [mock_conn]
        self.mock_server.datasources = Endpoint([mock_ds])

        # Workbooks
        self.mock_workbook = create_mock_object("workbook", 1)
        self.mock_server.workbooks = Endpoint([self.mock_workbook])
        self.mock_datasource = mock_ds

    def test__get_working_project__not_set(self):
        assert not self.tableau_wrapper._get_working_project()

    def test__get_working_project__id(self):
        r = self.tableau_wrapper._get_working_project(project_id="3")
        assert r.id == "3" and r.name == "project-3"

    def test___get_working_project__multiple_projects(self):
        with pytest.raises(self.tableau_wrapper.MultipleWorkingProjectsException):
            self.tableau_wrapper.project = "project-4"
            self.tableau_wrapper._get_working_project()

    def test__get_working_project__project_and_parent(self):
        self.tableau_wrapper.project = "project-4"
        self.tableau_wrapper.parent_project = "parent-project-1"
        r = self.tableau_wrapper._get_working_project()
        assert r.id == "4" and r.name == "project-4"

    def test___get_working_project__project(self):
        self.tableau_wrapper.project = "project-5"
        r = self.tableau_wrapper._get_working_project()
        assert r.id == "10" and r.name == "project-5"

    def test___get_working_project__unknown_project(self):
        with pytest.raises(self.tableau_wrapper.UnidentifiedWorkingProjectException):
            self.tableau_wrapper.project = "project-6"
            self.tableau_wrapper._get_working_project()

    def test_refresh_data_sources(self):
        r = self.tableau_wrapper.refresh_datasources(data_sources=["datasource-1"])
        assert r[0]["data_source"] == "datasource-1"

    def test_refresh_workbooks(self):
        r = self.tableau_wrapper.refresh_workbooks(work_books=["workbook-1"])
        assert r[0]["work_book"] == "workbook-1"
        # Positional: the parameter is ``workbook_id`` in 0.25 and
        # ``workbook_item`` from 0.34 on.
        self.mock_server.workbooks.refresh.assert_called_once_with(self.mock_workbook)

    def test_refresh_data_sources_positional(self):
        self.tableau_wrapper.refresh_datasources(data_sources=["datasource-1"])
        self.mock_server.datasources.refresh.assert_called_once_with(
            self.mock_datasource
        )

    def test__get_job_status(self, mocker):
        Scenario = namedtuple(
            "Scenario", ["job_id", "finish_code", "job_status", "polling_required"]
        )

        scenarios = [
            Scenario("1", -1, "Unknown", True),
            Scenario("2", -1, "Unknown", False),
            Scenario("3", 0, "Success", True),
            Scenario("4", 1, "Error", True),
            Scenario("5", 2, "Cancelled", True),
        ]

        for s in scenarios:
            job_response = mocker.MagicMock()
            timestamp = datetime.utcnow()
            job_response.finish_code = s.finish_code
            job_response.job_status = s.job_status
            job_response.started_at = timestamp
            job_response.completed_at = timestamp
            job_response.notes = "lorem ipsum"

            self.mock_server.jobs.get_by_id.return_value = job_response
            self.tableau_wrapper.polling_interval = 1
            self.tableau_wrapper.polling_timeout = 2
            self.tableau_wrapper.polling_required = s.polling_required

            result = self.tableau_wrapper._get_job_status(job_id=s.job_id)
            expect = {
                "job_id": s.job_id,
                "job_status": (
                    "Timeout"
                    if s.polling_required is True and s.finish_code == -1
                    else s.job_status
                ),
                "finish_code": (
                    -2
                    if s.polling_required is True and s.finish_code == -1
                    else s.finish_code
                ),
                "started_at": (
                    timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
                    if s.polling_required is True
                    else None
                ),
                "completed_at": (
                    timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
                    if s.polling_required is True
                    else None
                ),
                "job_status_details": "lorem ipsum" if s.finish_code == 1 else None,
            }
            assert result == expect

    def test__get_working_project__with_root(self):
        self.tableau_wrapper.project = "project-foo"
        self.tableau_wrapper.parent_project = "/"
        r = self.tableau_wrapper._get_working_project()
        assert r.id == "100" and r.name == "project-foo"
