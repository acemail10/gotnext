import React, { Component } from 'react';
import { connect } from 'react-redux';
import { bindActionCreators } from 'redux';
import axios from 'axios';

import { setGameSetting } from '../actions/setGameSetting';
import { setOption } from '../actions/setOption';
import { setLocation } from '../actions/setLocation';
import { setEditState } from '../actions/setEditState';
import { setUserGames } from '../actions/setUserGames';
import { Form, MenuItem, FormControl, Button, FormGroup, DropdownButton, InputGroup } from 'react-bootstrap';


class OptionCreate extends Component {
  constructor() {
    super();
    this.form = {
      sport: '',
      max: '',
      start: '',
      end: '',
      competitive: true,
      notes: '',
      address: '',
      coordinates: '',
      user: ''
    }
  }

  componentWillMount() {
    console.log('here is props edit', this.props.edit);
    if (this.props.edit === false) {
      this.props.setGameSetting({
        address: '',
        competitive: '',
        coordinates: '',
        end: '',
        max: '',
        notes: '',
        sport: '',
        start: '',
        user: this.props.user,
        token: window.localStorage.token,
        id: ''
      })
    }
  }

  componentDidUpdate() {
    if (this.props.edit === false) {
      console.log('hello world');
      if (this.props.setting) {
        var frm = document.getElementsByName('address');
        frm[0].value = this.props.setting.address;
        console.log('this is setting', this.props.setting);
        var frm = document.getElementsByName('sport');
        frm[0].value = this.props.setting.sport;
        var frm = document.getElementsByName('max');
        frm[0].value = this.props.setting.max;
        var frm = document.getElementsByName('start');
        frm[0].value = this.props.setting.start;
        var frm = document.getElementsByName('end');
        frm[0].value = this.props.setting.end;
        // var frm = document.getElementsByName('competitive');
        frm[0]['competitive'] = this.props.setting.competitive;
        var frm = document.getElementsByName('notes');
        frm[0].value = this.props.setting.notes;
      }
    }
  }

  componentDidMount() {
    if (this.props.edit === true) {
      if (this.props.setting) {
        var frm = document.getElementsByName('address');
        frm[0].value = this.props.setting.address;
        console.log('this is setting', this.props.setting);
        var frm = document.getElementsByName('sport');
        frm[0].value = this.props.setting.sport;
        var frm = document.getElementsByName('max');
        frm[0].value = this.props.setting.max;
        var frm = document.getElementsByName('start');
        frm[0].value = this.props.setting.start;
        var frm = document.getElementsByName('end');
        frm[0].value = this.props.setting.end;
        // var frm = document.getElementsByName('competitive');
        frm[0]['competitive'] = this.props.setting.competitive;
        var frm = document.getElementsByName('notes');
        frm[0].value = this.props.setting.notes;
      }
    }
  }

  onSubmitHandler() {
    console.log('click!');
    console.log('props', this.props.setting);
    if (this.props.edit === true) {
      console.log('true edit');
      console.log('editting!!!!', document.getElementsByName('address')[0].value);
      const payload = {
        address: document.getElementsByName('address')[0].value,
        competitive: this.props.setting.competitive,
        coordinates: this.props.location ? JSON.stringify(this.props.location) : this.props.setting.coordinates,
        end: document.getElementsByName('end')[0].value,
        max: parseInt(document.getElementsByName('max')[0].value),
        notes: document.getElementsByName('notes')[0].value,
        sport: document.getElementsByName('sport')[0].value,
        start: document.getElementsByName('start')[0].value,
        user: this.props.user,
        token: window.localStorage.token,
        id: this.props.setting.id
      }
      this.props.setGameSetting(payload);
      console.log('PAYYYYYLOAAAADDDD!!!!', payload);
      axios.put('/api/games/update', payload)
        .then((response) => {
          console.log('this is updated props.setting', this.props.setting)
          console.log('successfully editted game', response);
          axios.get(`/api/games/fetch/user/${this.props.user}`)
            .then((response) => {
              console.log('hello world', response);
              this.props.setUserGames(response.data);
              console.log('this is props.games', this.props.games);
              var frm = document.getElementsByName('address');
              frm[0].value = '';
              var frm = document.getElementsByName('sport');
              frm[0].value = '';
              var frm = document.getElementsByName('max');
              frm[0].value = '';
              var frm = document.getElementsByName('start');
              frm[0].value = '';
              var frm = document.getElementsByName('end');
              frm[0].value = '';
              // var frm = document.getElementsByName('competitive');
              // frm[0].value = false;
              var frm = document.getElementsByName('notes');
              frm[0].value = '';
              this.props.setLocation(null);
              console.log('this is location', this.props.location);
              // this.props.setGameSetting(null);
              this.props.setEditState(false);
              console.log('hello world');
              this.props.setOption('view');
            })
            .catch(() => {
              console.log('errrrror');
            })
        })
        .catch((err) => {
          console.log('error creating game', err);
        });
    } else {
      console.log('false edit');
      // var frm = document.getElementsByName('address');
      // frm[0].value = '';
      // var frm = document.getElementsByName('sport');
      // frm[0].value = '';
      // var frm = document.getElementsByName('max');
      // frm[0].value = '';
      // var frm = document.getElementsByName('start');
      // frm[0].value = '';
      // var frm = document.getElementsByName('end');
      // frm[0].value = '';
      // // var frm = document.getElementsByName('competitive');
      // // frm[0].value = false;
      // var frm = document.getElementsByName('notes');
      // frm[0].value = '';
      if (this.props.location) {
        const payload = this.form;
        payload['coordinates'] = this.props.location;
        payload['token'] = window.localStorage.token;
        payload['user'] = this.props.user;
        payload['competitive'] = this.form.competitive,
          console.log('here is payload false edit', payload);
        this.props.setGameSetting(payload);
        axios.post('/api/games/create', payload)
          .then((response) => {
            console.log('this is props.setting', this.props.setting)
            console.log('successfully created game', response);
            axios.get(`/api/games/fetch/user/${this.props.user}`)
              .then((response) => {
                var frm = document.getElementsByName('address');
                frm[0].value = '';
                var frm = document.getElementsByName('sport');
                frm[0].value = '';
                var frm = document.getElementsByName('max');
                frm[0].value = '';
                var frm = document.getElementsByName('start');
                frm[0].value = '';
                var frm = document.getElementsByName('end');
                frm[0].value = '';
                // var frm = document.getElementsByName('competitive');
                // frm[0].value = false;
                var frm = document.getElementsByName('notes');
                frm[0].value = '';
                console.log('hello world', response);
                this.props.setUserGames(response.data);
                console.log('this is props.games', this.props.games);
                this.props.setOption('view');
                // var frm = document.getElementsByName('address');
                // frm[0].value = '';
                // var frm = document.getElementsByName('sport');
                // frm[0].value = '';
                // var frm = document.getElementsByName('max');
                // frm[0].value = '';
                // var frm = document.getElementsByName('start');
                // frm[0].value = '';
                // var frm = document.getElementsByName('end');
                // frm[0].value = '';
                // var frm = document.getElementsByName('competitive');
                // frm[0].value = false;
                // var frm = document.getElementsByName('notes');
                // frm[0].value = '';
                this.props.setLocation(null);
                console.log('this is location', this.props.location);
                this.props.setGameSetting({});
              })
              .catch(() => {
                console.log('errrrror');
              })
          })
          .catch((err) => {
            console.log('error creating game', err);
          });
      } else {
        console.log('drop a pin!');
      }
    }
  }

  onChangeHandler(e) {
    this.form[e.target.name] = e.target.value;
    this.props.setting[e.target.name] = e.target.value;
    console.log(e.target.name, ', ', e.target.value, ' ... ', this.form[e.target.name]);
  }

  onSelectHandler(e) {
    this.form['competitive'] = e;
    this.props.setting.competitive = e;
    console.log('here is the address', this.form['address']);
    console.log('attempting to update setting', this.form['competitive']);
    console.log('this is the entire setting', this.props.setting);
    this.props.setGameSetting(this.props.setting);
    // frm[0]['competitive'] = this.props.setting.competitive;
    console.log('e: ', e, 'thisformcompetitive', this.form['competitive']);
  }

  render() {
    console.log('meeeow', this.props.setting);
    return (
      <div>
        {!this.props.edit ?
        <div style={{ fontSize: '14px', fontWeight: 'bold' }}>Create a Game:
        </div>
        :
        <div style={{ fontSize: '14px', fontWeight: 'bold' }}>Edit your game:
        </div>
        }
        <br />

        <Form >
          <FormGroup >
            <FormControl
              type="text"
              name="sport"
              placeholder="Sport"
              onChange={this.onChangeHandler.bind(this)}
            />
            <FormControl
              type="text"
              name="start"
              placeholder="Start time"
              onChange={this.onChangeHandler.bind(this)}
            />

            <FormControl
              type="text"
              name="end"
              placeholder="End time"
              onChange={this.onChangeHandler.bind(this)}
            />
            <FormControl
              type="text"
              name="address"
              placeholder="Address"
              onChange={this.onChangeHandler.bind(this)}
            />
            <FormControl
              type="text"
              name="max"
              placeholder="Max players"
              onChange={this.onChangeHandler.bind(this)}
            />

            <DropdownButton
              name="drop"
              componentClass={InputGroup.Button}
              id="input-dropdown-addon"
              title='Casual/Competitive'
              
            >
              <MenuItem eventKey={false} onSelect={this.onSelectHandler.bind(this)}>Casual
            </MenuItem>
              <MenuItem eventKey={true} onSelect={this.onSelectHandler.bind(this)}>Competitive
            </MenuItem>
            </DropdownButton>


            <FormControl
              style={{ resize: 'none' }}
              componentClass="textarea"
              type="text"
              name="notes"
              placeholder="Notes"
              onChange={this.onChangeHandler.bind(this)}
            />


          </FormGroup>
        </Form>

        <div>{!this.props.location && this.props.option === 'create' ? <div class='warn'>Please drop a pin to mark the location of the game.<br></br><br></br></div> : <div><br></br><br></br></div>}</div>

        {!this.props.edit ? <Button
          className="btns"
          block={true}
          type="button"
          bsStyle="primary"
          onClick={this.onSubmitHandler.bind(this)}
        >Create!
        </Button> : <Button
            className="btns"
            block={true}
            type="button"
            bsStyle="primary"
            onClick={this.onSubmitHandler.bind(this)}
          >Edit
        </Button>}


      </div>



    )


  }
}

const mapStateToProps = state => {
  return {
    location: state.location,
    setting: state.setting,
    user: state.user,
    games: state.games,
    edit: state.edit,
    option: state.option
  }
};

const matchDispatchToProps = dispatch => {
  return bindActionCreators({
    setEditState: setEditState,
    setGameSetting: setGameSetting,
    setUserGames: setUserGames,
    setLocation: setLocation,
    setOption: setOption
  },
    dispatch);
};

export default connect(mapStateToProps, matchDispatchToProps)(OptionCreate);