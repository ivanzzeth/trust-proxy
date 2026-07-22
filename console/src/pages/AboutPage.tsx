import { About } from '~/components/about/About';
import { connect } from '~/components/StateProvider';
import { getClashAPIConfig } from '~/store/app';
import { State } from '~/store/types';

const mapState = (state: State) => ({
  apiConfig: getClashAPIConfig(state),
});

export default connect(mapState)(About);
