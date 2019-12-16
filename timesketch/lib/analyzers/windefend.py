
"""Sketch analyzer plugin for windefend."""
from __future__ import unicode_literals

from timesketch.lib import emojis
from timesketch.lib.analyzers import interface
from timesketch.lib.analyzers import manager


class WindefendSketchPlugin(interface.BaseSketchAnalyzer):
    """Sketch analyzer for Windefend."""

    NAME = 'windefend'

    DEPENDENCIES = frozenset()

    def __init__(self, index_name, sketch_id):
        """Initialize The Sketch Analyzer.

        Args:
            index_name: Elasticsearch index name
            sketch_id: Sketch ID
        """
        self.index_name = index_name
        super(WindefendSketchPlugin, self).__init__(index_name, sketch_id)

    def run(self):
        """Entry point for the analyzer.

        Returns:
            String with summary of the analyzer result
        """
        # TODO: Add Elasticsearch query to get the events you need.
        query = ('(event_identifier:"1116" '
                'AND data_type:"windows:evtx:record")')

        # TODO: Specify what returned fields you need for your analyzer.
        return_fields = ['event_identifier', 'data_type']

        # Generator of events based on your query.
        # Swap for self.event_pandas to get pandas back instead of events.
        events = self.event_stream(
            query_string=query, return_fields=return_fields)

        # TODO: If an emoji is needed fetch it here.
        # my_emoji = emojis.get_emoji('emoji_name')
        skull_crossbone = emojis.get_emoji('skull_crossbone')

        windefend_count = 0

        # TODO: Add analyzer logic here.
        # Methods available to use for sketch analyzers:
        # sketch.get_all_indices()
        # (If you add a view, please make sure the analyzer has results before
        # adding the view.)
        # sketch.add_view(
        #     view_name=name, analyzer_name=self.NAME,
        #     query_string=query_string, query_filter={})
        # event.add_attributes({'foo': 'bar'})
        # event.add_tags(['tag_name'])
        # event_add_label('label')
        # event.add_star()
        # event.add_comment('comment')
        # event.add_emojis([my_emoji])
        # event.add_human_readable('human readable text', self.NAME)
        # Remember you'll need to add event.commit() once all changes to the
        # event have been completed.
        for event in events:
            data_type = event.source.get('data_type')
            event_identifier = event.source.get('event_identifier')

            event.add_tags('Defender Detection')

            windefend_count +=1

            event.add.emojis(skull_crossbone)
            event.commit()

        if windefend_count:
            self.sketch.add_view('Defender Activity', 'windefend', query_string=query)

        # TODO: Return a summary from the analyzer.
        return 'Windefend analyzer completed, {0:d} Windows Defender items found'.format(windefend_count)


manager.AnalysisManager.register_analyzer(WindefendSketchPlugin)
